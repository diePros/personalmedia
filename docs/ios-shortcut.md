# Share to PMS from an iPhone or iPad (Shortcut)

iOS Safari has no Web Share Target, so the installed app does not appear in the iOS share sheet. One iOS Shortcut fills the gap. **You, the owner, build it once** on your iPhone from this recipe and share it as an iCloud link. Every user (you included) then gets a "Get the Shortcut" button in Settings plus a personal setup code to paste into the Shortcut.

The Shortcut uploads to `{URL}/api/upload` with a bearer token. That works because `/api/upload` accepts bearer `read_write` tokens, and the origin guard exempts bearer requests on that route. There is no review page: files are stored right away, tagged `inbox`, and you sort them later in the web UI.

## Build the Shortcut (owner, once)

Open the **Shortcuts** app, tap **+** to make a new shortcut and add these actions in order.

1. Tap the name at the top and rename the shortcut to **PMS**.
2. Tap the **(i)** button (Shortcut Details). Turn on **Show in Share Sheet**. Under share sheet types leave only **Images**, **PDFs** and **Files** selected.
3. The first action is **Receive [Images, PDFs, Files] input from Share Sheet**. Set *If there's no input* to **Stop and Respond**.
4. Add a **Text** action. Put a placeholder in it, for example `https://example.com|pm_placeholder`. This holds the setup code.
   - Open the shortcut's **(i)** details, go to **Setup**, and add an **Import Question** for this Text action.
   - Question: `Paste your PMS setup code (Settings → iPhone & iPad sharing)`.
   - The imported answer replaces the Text on each device, so your own code never travels with the link.
5. Add **Split Text** on that Text. Choose **Custom** and enter `|` as the separator.
6. Add **Get Item from List** and choose **First Item** (the URL). Add **Set Variable** `URL`. Add a second **Get Item from List** on the Split Text, with **Item at Index** `2` (the token), and **Set Variable** `Token`.
7. Add **Count** on **Shortcut Input** with *Items*. Then add **If** *Count* **is greater than** `1`.
   - Inside the **If**: add **Make PDF** on **Shortcut Input**. The images become one PDF document.
   - Add **Set Variable** `Upload` to the PDF.
   - **Otherwise**: **Set Variable** `Upload` to **Shortcut Input**.
   - **End If**.
8. Add **Get Contents of URL**:
   - URL: the `URL` variable followed by `/api/upload`.
   - Expand it with the arrow. **Method**: **POST**.
   - **Headers** → **Add new header**: key `Authorization`, text `Bearer ` followed by the `Token` variable (the word Bearer, a space, then the variable).
   - **Request Body**: **Form**. **Add new field** → **File**: key `file`, value the `Upload` variable.
9. Add **Get Dictionary Value** for the key `error` from **Contents of URL**.
10. Add **If** *Dictionary Value* **has any value**. Inside, **Show Notification** with the dictionary value (the error message). **Otherwise**, **Show Notification** with the text `Saved to PMS`. **End If**.
11. Tap **Done**.

If iOS asks you to allow "untrusted shortcuts" when someone imports it, they need to enable that in Settings → Shortcuts only if prompted. Links from iCloud normally do not need it.

## Publish the link

1. In the Shortcuts app, long-press the shortcut → **Share** → **Copy iCloud Link**.
2. Set `PM_IOS_SHORTCUT_URL` to it (for example `https://www.icloud.com/shortcuts/0123456789abcdef0123456789abcdef`) and restart the container. Only links of the form `https://www.icloud.com/shortcuts/<32 hex characters>` are accepted; anything else is ignored with a warning in the log.
3. Open **Settings → iPhone & iPad sharing** to try it yourself.

## For your friends

1. Open PMS in Safari and sign in. In **Settings**, find **iPhone & iPad sharing**, type your password and press **Set up iPhone sharing**.
2. Tap **Get the Shortcut** and add it.
3. When the Shortcut asks for the setup code, paste the one from the page (press **Copy** first). The code is shown only once; you can repeat the setup at any time.

Then share any photo, PDF or file with **PMS** from the share sheet. Several images shared together become one PDF.

## Security notes

- The iCloud link contains no token. The setup code is entered on each device through the import question.
- Each setup creates a new token named "iPhone Shortcut". It has `read_write` access, `metadata_only` content and is restricted to the `inbox` tag, so it can add files and see only the metadata of `inbox` documents. Old tokens stay valid until revoked, so revoke earlier iPhone tokens in **Settings → Tokens**.
- The token is stored on the phone inside the Shortcut. If the phone is lost, revoke the "iPhone Shortcut" token in **Settings → Tokens**; it stops working at once.
- Uploads over `PM_MAX_UPLOAD_MB` (default 100) are rejected with an error notification. Duplicates of files already in the vault are skipped.
