# Minor-2
The rapid growth in the number of smart devices and related connectivity loads has impacted mobile services seamlessly offered anywhere around the globe .In such connected world, the enabler keeping the transmitted data secure is difficult ,so we need an additional level of security.This additional security layer can be achieved by using two-factor authentication making it much harder for hackers to break into your accounts.
In this project, the server generates a secret key for a user and then stores the secret key in the database associated with the user account.After that QR image URL is returned. Now, User uses the image to load the secret key into his authenticator application,either by entering the secret key or directly loading the key by scanning the QR code. Whenever the user logs in, the user enters the number from the authenticator application into the login form.This number continuously keeps on changing after the same interval of time. The server compares the secret code entered by the user with the output . If the values match then the user is allowed to log in. 