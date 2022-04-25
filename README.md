# Minor-2
The rapid growth in the number of smart devices and related connectivity loads has impacted mobile services seamlessly offered anywhere around the globe .In such connected world, the enabler keeping the transmitted data secure is difficult ,so we need an additional level of security.This additional security layer can be achieved by using two-factor authentication making it much harder for hackers to break into your accounts.
In this project, the server generates a secret key for a user and then stores the secret key in the database associated with the user account.After that QR image URL is returned. Now, User uses the image to load the secret key into his authenticator application,either by entering the secret key or directly loading the key by scanning the QR code. Whenever the user logs in, the user enters the number from the authenticator application into the login form.This number continuously keeps on changing after the same interval of time. The server compares the secret code entered by the user with the output . If the values match then the user is allowed to log in. 
Dependencies:- 
For our project we need a stable internet connection so that users can easily access QR Image using the internet and validate it quickly.
For the OTP generate process, we need server having less downtime 
Maven Dependencies-
Commons-codec-1.6.jar
Hamcrest-core-1.3.jar
junit-4.13.2.jar

*Classes*
•	class TwoFactor:
This class acts as the driver class. The generated secret key is displayed in the main function of this class. The function where the secret key is generated is called in this class. After displaying the secret key, the QR image URL is also displayed using which the user can directly load the key in their device. Then the secret code is displayed after the specified time interval i.e., 30 seconds. To display this code, the method which returns it is called here.
•	class TOTPAuth:
       This class is responsible for all the computing. The secret key and the rapidly changing secret codes are updated in the methods of this class. The QR image and its URL are also generated in this class.
