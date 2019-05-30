using System;
using Refinitiv.EDP.AutoRest.Alerts;
using Refinitiv.EDP.AutoRest.Alerts.Models;
using Refinitiv.EDP.AutoRest.Auth.OAuth2;
using Refinitiv.EDP.AutoRest.Auth.OAuth2.Models;
using Refinitiv.EDP.AutoRest.Auth.CloudCredentials;
using Refinitiv.EDP.AutoRest.Auth.CloudCredentials.Models;
using Microsoft.Rest;
using Newtonsoft.Json.Linq;
using Amazon.SQS;
using Amazon.SQS.Model;
using Amazon.Runtime;
using System.Text;
using System.Collections.Generic;
using NSec.Cryptography;
using AuthError = Refinitiv.EDP.AutoRest.Auth.OAuth2.Models.Error;
using AlertsError = Refinitiv.EDP.AutoRest.Alerts.Models.Error;
using CloudCredentialsError = Refinitiv.EDP.AutoRest.Auth.CloudCredentials.Models.Error;
using Newtonsoft.Json;

namespace EDPAlertsExample
{
    class Program
    {
        public string DecryptMessage(
            string encryptedText, 
            string cryptographyKey)
        {
            int ivSize = 12;            
            int aadSize = 16;

            var cryptographyKeyByte = Convert.FromBase64String(cryptographyKey);
            var encryptedByte = Convert.FromBase64String(encryptedText);
            var aes = new Aes256Gcm();

            var aad = new byte[aadSize];
            Array.Copy(encryptedByte, 0, aad, 0, aadSize);

            var iv = new byte[ivSize];
            Array.Copy(aad, 4, iv, 0, ivSize);

            var key = Key.Import(aes,
                cryptographyKeyByte,
                KeyBlobFormat.RawSymmetricKey);

            var encryptedByteNoAad = new byte[encryptedByte.Length - aadSize];
            Array.Copy(encryptedByte, aadSize, encryptedByteNoAad, 0, encryptedByteNoAad.Length);

            byte[] decryptedByte;
            aes.Decrypt(key, new Nonce(iv, 0), aad, encryptedByteNoAad, out decryptedByte);

            return Encoding.UTF8.GetString(decryptedByte);
        }

        public Program()
        {

        }
        public List<string> RetrieveMessages(
            CredentialDetails credDetails,
            int numberOfMessages
            )
        {
            var sqsConfig = new AmazonSQSConfig();
            List<string> headlineList = new List<string>();
         
            Uri endPointUri = new Uri(credDetails.Endpoint);
            sqsConfig.ServiceURL = $"{endPointUri.Scheme}://{endPointUri.Host}";

            var awsCredentials = new SessionAWSCredentials(
                credDetails.Credentials.AccessKeyId,
                credDetails.Credentials.SecretKey,
                credDetails.Credentials.SessionToken);
           

            var sqsClient = new AmazonSQSClient(
                awsCredentials,
                sqsConfig);


            var receiveMessageRequest = new ReceiveMessageRequest {
                QueueUrl = credDetails.Endpoint,
                MaxNumberOfMessages = 10
            };

            ReceiveMessageResponse receiveMessageResponse = null;
            while (receiveMessageResponse == null || headlineList.Count < numberOfMessages)
            {
                receiveMessageResponse = sqsClient.ReceiveMessageAsync(receiveMessageRequest).
                  GetAwaiter().
                  GetResult();
                
                foreach(var message in receiveMessageResponse.Messages)
                {                    
                    if (headlineList.Count < numberOfMessages)
                    {
                        headlineList.Add(message.Body);
                    }
                    DeleteMessageRequest deleteMessageRequest = new DeleteMessageRequest();

                    deleteMessageRequest.QueueUrl = credDetails.Endpoint;
                    deleteMessageRequest.ReceiptHandle = message.ReceiptHandle;
                    DeleteMessageResponse response =
                            sqsClient.DeleteMessageAsync(deleteMessageRequest).GetAwaiter().GetResult();
                }
            }        
            
            return headlineList;         
        }
        public CredentialDetails GetCloudCredentials(
            Tokenresponse token, 
            NewsSubscriptionDetails newsSub, 
            out string error)
        {
            TokenCredentials cred = new TokenCredentials(token.AccessToken);
            CloudCredentialsAPI cloudCredential = new CloudCredentialsAPI(cred);
            var response = cloudCredential.Get(newsSub.TransportInfo.Endpoint);

            if (response is CredentialDetails)
            {
                error = null;
                return (CredentialDetails)response;

            }
            else if (response is CloudCredentialsError)
            {
                error = ((CloudCredentialsError)response).ErrorProperty.Message;
                return null;
            }
            else
            {
                error = "Unknown Type";
                return null;
            }
        }
        public NewsSubscriptionDetails SubscribeNewsHeadlines(
            Tokenresponse token, 
            JObject newsFilter, 
            out string error)
        {
            TokenCredentials cred = new TokenCredentials(token.AccessToken);
            SubscriptionstocontentalertsAPI alerts = new SubscriptionstocontentalertsAPI(cred);
            var response = alerts.PostNewsHeadlinesSubscriptions(new NewNewsSubscription { Filter = newsFilter });

            
            if (response is NewsSubscriptionDetails)
            {
                error = null;
                return (NewsSubscriptionDetails)response;
            }
            else if(response is AlertsError)
            {                
                error = ((AlertsError)response).ErrorProperty.Message;
                return null;
            }
            else
            {
                error = "Unknown Type";
                return null;
            }
        }
        public Tokenresponse Login(
            string username,
            string password,
            string clientid,
            out string error)
        {
            EDSAuthentication eds = new EDSAuthentication();            
            
            var response = eds.PostToken(
                "password",
                username,
                password,
                null,
                "trapi", 
                null,
                clientid,
                "true");

            if (response is Tokenresponse)
            {
                Tokenresponse tokenResp = (Tokenresponse)response;
                error = null;
                return (Tokenresponse)response;
                
            }
            else if (response is AuthError)
            {
                error = ((AuthError)response).ErrorDescription;
                return null;
            }
            else
            {
                error = "Unknown Type";
                return null;
            }

        }

        public AlertsError Unsubscribe(
            Tokenresponse token,
            NewsSubscriptionDetails newsSubscriptionDetails
           )
        {
            TokenCredentials cred = new TokenCredentials(token.AccessToken);
            SubscriptionstocontentalertsAPI alerts = new SubscriptionstocontentalertsAPI(cred);
            return alerts.DeleteNewsHeadlinesSubscriptions(newsSubscriptionDetails.SubscriptionID);           
        }
       
        public void run()
        {
            string error;
            string username = "<username>";
            string password = "<password>";
            string appId = "<application id>";


            Console.WriteLine("1. Login ...");
            var tokenResponse = Login(
                username,
                password,
                appId,
                out error);

            if(tokenResponse == null)
            {
                Console.WriteLine($"Login error: {error}");
                return;
            }
            Console.WriteLine($"\t Access token: {tokenResponse.AccessToken}\n");
            Console.WriteLine("2. Subscribe news headlines ...");

            var newsSub = SubscribeNewsHeadlines(
                tokenResponse,
                JObject.FromObject(
                    new {  language = "en"    }
                    ), 
                out error
                );

            if (newsSub == null)
            {
                Console.WriteLine($"News headlines subscription error: {error}");
                return;
            }
            Console.WriteLine($"\t Endpoint URL: {newsSub.TransportInfo.Endpoint}\n");

            Console.WriteLine("3. Get cloud credentials  ...");

            var cloudCred = GetCloudCredentials(tokenResponse, newsSub, out error);
            if (cloudCred == null)
            {
                Console.WriteLine($"Get cloud credentials error: {error}");
                return;
            }
            Console.WriteLine($"\t Access Key ID: {cloudCred.Credentials.AccessKeyId}\n");
            Console.WriteLine("4. Retrieve messages ...\n");

            var messages = RetrieveMessages(cloudCred, 20);

            Console.WriteLine($"5. Decrypt messages [{messages.Count}]  ...");
            foreach (var message in messages)
            {         
                var headline = DecryptMessage(message, newsSub.TransportInfo.CryptographyKey);
                var obj = JObject.Parse(headline);
           
                if (obj["payload"]["newsMessage"]["itemSet"]["newsItem"][0]["itemMeta"]["title"][0] != null)
                {
                    Console.WriteLine($"{obj["contentReceiveTimestamp"]}: {obj["payload"]["newsMessage"]["itemSet"]["newsItem"][0]["itemMeta"]["title"][0]["$"]}" );
                }
            }

            Console.WriteLine("6. Unsubscribe ...");
            var alertError = Unsubscribe(tokenResponse, newsSub);
            if (alertError != null)
            {                
                Console.WriteLine($"Unsubscribe error: {alertError.ErrorProperty.Message}");
            }

        }
         
        static void Main(string[] args)
        {
            Console.WriteLine("News Headlines Subscription ...");

            Program prog = new Program();
            prog.run();        
        
        }
    }
}
