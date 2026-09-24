'use strict';
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');
const logger = require('./logger');

const TOKEN_PATH = path.join(__dirname, '../../tokens/google_token.json');
const REFRESH_MARGIN_MS = 30 * 60 * 1000; // 30分前にプロアクティブリフレッシュ（旧: 10分）
const REFRESH_TOKEN_WARN_AGE_MS = 5 * 24 * 60 * 60 * 1000; // 5日で警告（余裕を持つ）
const REFRESH_TOKEN_MAX_AGE_MS = 6 * 24 * 60 * 60 * 1000;  // 6日で危険

function loadTokenJson() {
  if (process.env.RENDER_GOOGLE_TOKEN_JSON) {
    return JSON.parse(process.env.RENDER_GOOGLE_TOKEN_JSON);
  }
  if (fs.existsSync(TOKEN_PATH)) {
    return JSON.parse(fs.readFileSync(TOKEN_PATH, 'utf8'));
  }
  throw new Error('Googleトークンが見つかりません。node tools/setup.js を実行して認証してください');
}

/** トークンファイルに保存（ディレクトリ存在時のみ） */
function saveTokenJson(tokenData) {
  const dir = path.dirname(TOKEN_PATH);
  if (fs.existsSync(dir)) {
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokenData, null, 2));
    logger.info('google_auth', 'トークンファイルを更新しました');
  }
}

/**
 * refresh_token の健全性チェック
 * @returns {{ healthy: boolean, daysLeft: number|null, message: string }}
 */
function checkTokenHealth() {
  try {
    const tokenJson = loadTokenJson();

    // refresh_token_expires_in があれば7日制限（テストモード）を検出
    if (tokenJson.refresh_token_expires_in) {
      const expiresInSec = tokenJson.refresh_token_expires_in;
      const createdAt = tokenJson.refresh_token_created_at || 0;
      const expiresAt = createdAt + expiresInSec * 1000;
      const msLeft = expiresAt - Date.now();
      const daysLeft = msLeft / 86400000;

      if (msLeft <= 0) {
        return {
          healthy: false,
          daysLeft: 0,
          message: `refresh_tokenは既に失効しています（${Math.abs(Math.floor(daysLeft))}日前）。Google Cloud ConsoleでOAuthアプリを「本番」モードに変更し、node tools/setup.js を再実行してください`,
        };
      }
      if (daysLeft < 2) {
        return {
          healthy: false,
          daysLeft: Math.floor(daysLeft),
          message: `refresh_tokenの残り寿命: ${daysLeft.toFixed(1)}日。Google Cloud ConsoleでOAuthアプリを「本番」モードに変更してください（テストモードでは7日で失効します）`,
        };
      }
      // テストモードの警告（まだ動作はする）
      return {
        healthy: true,
        daysLeft: Math.floor(daysLeft),
        message: `⚠️ テストモード検出: refresh_tokenの残り${daysLeft.toFixed(1)}日。本番モードに変更すれば無期限になります`,
      };
    }

    // refresh_token_created_at ベースのチェック（フォールバック）
    // 注: これは「テストモードでの7日失効」を推定するためのヒューリスティックにすぎない。
    // 本番モードでは refresh_token は経過日数では失効しないため、日数だけで失効と
    // 断定して処理を停止させない（実際の生存判定は refreshAccessToken() の成否に委ねる）。
    if (tokenJson.refresh_token_created_at) {
      const age = Date.now() - tokenJson.refresh_token_created_at;
      const daysOld = age / 86400000;
      if (age > REFRESH_TOKEN_WARN_AGE_MS) {
        return {
          healthy: true,
          daysLeft: null,
          message: `refresh_tokenが${Math.floor(daysOld)}日経過（本番モードなら失効しません）。念のため動作を確認してください`,
        };
      }
    }

    return { healthy: true, daysLeft: null, message: 'トークンは正常です' };
  } catch (e) {
    return { healthy: false, daysLeft: null, message: `トークン読み込みエラー: ${e.message}` };
  }
}

async function getAuthClient() {
  let tokenJson;
  try {
    tokenJson = loadTokenJson();
  } catch (e) {
    throw new Error(`Google認証エラー: ${e.message}`);
  }

  // refresh_token の健全性チェック
  const health = checkTokenHealth();
  if (!health.healthy) {
    logger.error('google_auth', health.message);
  } else if (health.daysLeft !== null && health.daysLeft < 5) {
    logger.warn('google_auth', health.message);
  }

  const oauth2 = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/oauth/callback'
  );
  oauth2.setCredentials(tokenJson);

  // プロアクティブリフレッシュ: 期限30分前 OR 期限が不明な場合は毎回リフレッシュ試行
  const expiry = tokenJson.expiry_date;
  const needsRefresh = !expiry || Date.now() > expiry - REFRESH_MARGIN_MS;

  if (needsRefresh) {
    try {
      logger.info('google_auth', 'アクセストークンを自動リフレッシュ中...');
      const { credentials } = await oauth2.refreshAccessToken();
      oauth2.setCredentials(credentials);

      // リフレッシュ成功 → refresh_token_created_at をリセット（生存証明）
      const merged = {
        ...tokenJson,
        ...credentials,
        // リフレッシュ成功はトークンが生存している証拠なので、鮮度タイムスタンプを
        // 常に更新する。これにより経過日数ベースの誤検知（本番モードでのfalse positive）を防ぐ。
        refresh_token_created_at: Date.now(),
      };
      saveTokenJson(merged);
      logger.info('google_auth', 'アクセストークンのリフレッシュ完了');
    } catch (e) {
      const detail = e?.response?.data?.error || e.message || String(e);
      const isInvalidGrant = detail === 'invalid_grant' || String(e).includes('invalid_grant');

      if (isInvalidGrant) {
        logger.error('google_auth', 'INVALID_GRANT検出 — refresh_token失効', { error: detail });
        const err = new Error(
          'INVALID_GRANT: refresh_tokenが失効しました。\n\n' +
          '【恒久修正】Google Cloud Console > OAuth同意画面 > 公開ステータスを「本番」に変更\n' +
          '（テストモードではrefresh_tokenが7日で自動失効します）\n\n' +
          '【応急処置】node tools/setup.js を再実行し、GitHub SecretsとRenderのRENDER_GOOGLE_TOKEN_JSONを両方更新してください'
        );
        err.code = 'INVALID_GRANT';
        throw err;
      }

      // INVALID_GRANT以外のリフレッシュ失敗（ネットワーク障害等）
      // → access_tokenがまだ有効かもしれないので、スロー前に一度APIを試す
      logger.warn('google_auth', `リフレッシュ失敗（${detail}）。既存トークンで続行を試みます`);
    }
  }

  return oauth2;
}

module.exports = { getAuthClient, checkTokenHealth };
