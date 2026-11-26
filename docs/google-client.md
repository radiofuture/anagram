# Set up a Google client for your lab

Anagram reads Google Drive and Gmail with a Google OAuth client. Until
Google verifies a Radiofuture client for these scopes, each lab uses its own
client in its own Google Workspace. This page is for the
lab admin who does this one time. It takes about 15 minutes.

What you need:

- An account in the Google Workspace of your lab or university, with the
  right to make a Google Cloud project. Ask your Workspace admin if you do
  not have it.
- The PI or admin role in the lab in Anagram.

Personal `gmail.com` accounts cannot use a client of type "Internal". Only
accounts of the same Workspace can sign in with it.

## 1. Make a project

1. Open the Google Cloud console (console.cloud.google.com) with your
   Workspace account.
2. Make a new project. Use a name that your members know, for example
   "Anagram for the Lee Lab". Select the organization of your Workspace.

## 2. Turn on the two APIs

1. Go to "APIs and services", then "Library".
2. Find "Google Drive API" and click Enable.
3. Find "Gmail API" and click Enable.

## 3. Set the consent screen

1. Go to "APIs and services", then "OAuth consent screen" (in newer consoles:
   "Google Auth Platform", then "Branding" and "Audience").
2. User type: **Internal**. With Internal, Google does not need to verify the
   app, and the sign-in does not expire after 7 days.
3. App name: the name of your project. Support email: your address.
4. Scopes ("Data access"): add these three, and no other:
   - `openid` and `.../auth/userinfo.email` (the address of the member)
   - `https://www.googleapis.com/auth/drive.readonly` (read Drive)
   - `https://www.googleapis.com/auth/gmail.readonly` (read Gmail)

Anagram only reads. It never asks to change, send, or delete.

## 4. Make the client

1. Go to "APIs and services", then "Credentials" (or "Google Auth Platform",
   then "Clients").
2. Click "Create credentials", then "OAuth client ID".
3. Application type: **Desktop app**. Name: "Anagram".
4. Click Create. Copy the **client ID** and the **client secret**.

The secret of a desktop client is not confidential: Google documents that an
app on a person's computer cannot keep it. It is safe in the lab settings,
which only the members of your lab can read. Do not put it in a public place.

## 5. Put the client into the lab settings

1. In Anagram, open the lab, then **Lab settings**.
2. In **Google client**, paste the client ID and the client secret, and save.

You can also do this in **Sources**: select **Google Drive** or **Gmail**
(the tile says "Not set up for this lab"). For a PI or lab admin, the same
two fields show there. After a save, Anagram shows the secret only as "A
secret is set". It does not show the value again.

A Notion client goes into **Notion client** in the same way (a public
integration with "Read content" only).

Each member of the lab gets the setting with the next lab sync. "Google
Drive" and "Gmail" then show as available in **Add a source**.

## 6. If your Workspace limits apps

Some Workspace admins permit only trusted apps to read Drive or Gmail. If a
member sees "Access blocked" in the Google sign-in:

1. The Workspace admin opens admin.google.com, then "Security", "Access and
   data control", "API controls".
2. In "App access control", find the client ID of step 4 and set it to
   **Trusted**.

## What Google and you can see

- Google sees which files and messages Anagram reads, and when. Google does
  not see the index.
- In the Cloud console you see request counts. You do not see tokens or
  content.
- The sign-in of each member stays in the keychain of that member's computer.
  Nobody else gets it.

## Remove the client

Delete the client in the Cloud console, then remove it from the lab
settings. The Drive and Gmail sources of your members then ask them to sign
in again, and they cannot until the lab has a new client.
