// Basic 認証（サイト全体に鍵をかける）
// ユーザー名とパスワードはコードに書かず、Cloudflare の環境変数から読み込む
//   BASIC_USER : ユーザー名
//   BASIC_PASS : パスワード
// どちらも Cloudflare Pages の「設定 → 変数とシークレット」に「シークレット」として登録する

export async function onRequest(context) {
  const { request, env, next } = context;
  const expectedUser = env.BASIC_USER;
  const expectedPass = env.BASIC_PASS;

  // 環境変数が未設定のときは、鍵が開いたままにならないよう誰も入れないようにする
  if (!expectedUser || !expectedPass) {
    return new Response('認証の設定が完了していません。', {
      status: 503,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }

  const credentials = parseBasicAuth(request.headers.get('Authorization'));
  if (credentials) {
    // ユーザー名とパスワードを両方とも確認する（&& の短絡で処理時間に差が出ないよう、先に両方比べる）
    const userOk = await safeEqual(credentials.user, expectedUser);
    const passOk = await safeEqual(credentials.pass, expectedPass);
    if (userOk && passOk) {
      return next();
    }
  }

  // 認証されていなければ、ブラウザにログイン画面を出させる
  return new Response('認証が必要です。', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="work-checklist", charset="UTF-8"',
      'Content-Type': 'text/plain; charset=utf-8',
    },
  });
}

// 「Authorization: Basic xxxx」からユーザー名とパスワードを取り出す
function parseBasicAuth(header) {
  if (!header || !header.startsWith('Basic ')) return null;
  try {
    // Base64 をバイト列に戻し、日本語などのパスワードにも対応するため UTF-8 として読む
    const binary = atob(header.slice(6).trim());
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    const decoded = new TextDecoder().decode(bytes);
    const sep = decoded.indexOf(':');
    if (sep < 0) return null;
    return { user: decoded.slice(0, sep), pass: decoded.slice(sep + 1) };
  } catch {
    return null;
  }
}

// 文字列を比べる。一致するまでの時間からパスワードを推測されないよう、
// ハッシュ値（長さが常に同じ）にしてから一定時間で比較する
async function safeEqual(a, b) {
  const encoder = new TextEncoder();
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(hashA, hashB);
}
