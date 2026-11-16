# Share to Personal Media from an iPhone or iPad (Shortcut)

iOS Safari does not support the Web Share Target that Android uses, so the installed app does not appear in the iOS share sheet. An iOS Shortcut fills the gap: it sends the shared files straight to the upload API of your Personal Media server. Unlike the Android flow there is **no review page**; the files are stored right away, so use a dedicated token that can only add documents with an `inbox` tag, and sort them later in the web UI.

You need the server's public URL (`PM_PUBLIC_URL`, for example `https://node.tailnet.ts.net`) and a token.

## 1. Create a dedicated token

1. In the web UI open **Settings → Tokens → New token**.
2. Name it something like `iPhone share`.
3. Choose these options:
   - Access: **`read_write`** (an upload needs write access).
   - Content level: **`metadata_only`**. The Shortcut only uploads; it never needs to read document text.
   - Tag allow-list: **`inbox`**. Every upload made with this token is tagged `inbox`, and the token cannot see or touch documents outside that tag.
4. Copy the token (`pm_…`). It is shown only once.

## 2. Build the Shortcut

Open the **Shortcuts** app, tap **+** (new shortcut) and add these actions in order.

1. Tap the name at the top and rename the shortcut to **Share to Personal Media**.
2. Tap the **(i)** button (Shortcut Details):
   - Turn on **Show in Share Sheet**.
   - Under **Share Sheet Types** deselect everything except **Images**, **PDFs** and **Files** (add **Text** only if you also want to share `.txt` files).
3. In the first action, "Receive **Images, PDFs and Files** input from **Share Sheet**", set *If there's no input* to **Stop and Respond** (or *Ask For* if you also want to run the shortcut by hand).
4. Add **Repeat with Each**. Its input is **Shortcut Input**, so the shortcut also works when you share several files at once.
5. Inside the loop add **Get Contents of URL**:
   - **URL**: your server, followed by `/api/upload`, for example `https://node.tailnet.ts.net/api/upload`.
   - Tap the arrow to expand it, then **Method**: **POST**.
   - **Headers** → **Add new header**: key `Authorization`, text `Bearer pm_…` (the word `Bearer`, a space, then your token).
   - **Request Body**: **Form**.
   - **Add new field** → **File**: key `file`, value **Repeat Item** (tap the value and choose the magic variable *Repeat Item*).
   - Optional: to set a title, add a **Text** field first with key `title` and the value you want. Text fields must come **before** the `file` field, because the server streams the file and ignores everything after it.
6. After the loop (outside **Repeat with Each**, at the very bottom) add **Show Result**, or **Show Notification** with *Contents of URL* if you prefer a banner. It shows `{"status":"stored","id":"…"}` for a new document or `{"status":"duplicate",…}` if the same file is already in your vault (duplicates are skipped and not stored twice).
7. Tap **Done**.

## 3. Use it

In Photos, Files, Safari or any other app: tap **Share**, scroll down and choose **Share to Personal Media**. The first run asks iOS for permission to contact your server's domain; allow it. Then open the web UI and look at the `inbox` tag to give the new documents proper titles and tags.

Limits: the server rejects a file over `PM_MAX_UPLOAD_MB` (default 100 MB) with HTTP 413, which the result view shows as an error.

## 4. About the token on your phone

The token is stored **in plain text inside the Shortcut on your phone** (and is included in iCloud if Shortcuts sync is on, and in any copy of the Shortcut you share with someone else). Anyone who can open the Shortcut can read it. That is why the token is restricted to `read_write`, `metadata_only` and the `inbox` tag: even if it leaks, it can add files tagged `inbox` and see only documents already in that tag, never your other documents and never their text.

Do not share the Shortcut file with anyone; share a fresh Shortcut with their own token instead.

**To revoke it** (phone lost, Shortcut shared by mistake, or you simply stopped using it): open the web UI, go to **Settings → Tokens** and revoke the `iPhone share` token. It stops working immediately. To use the Shortcut again, create a new token and replace the `Authorization` header in the **Get Contents of URL** action.
