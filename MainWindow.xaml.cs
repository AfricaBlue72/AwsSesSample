using Amazon;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.SimpleEmail;
using Amazon.SimpleEmail.Model;
using Amazon.SQS;
using Amazon.SQS.Model;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

/* 
 * Amazon.Extensions.CognitoAuthentication
 * https://www.nuget.org/packages/Amazon.Extensions.CognitoAuthentication/2.0.3?_src=template
 * https://github.com/aws/aws-sdk-net-extensions-cognito/
 */

/* 
 * Microsoft.IdentityModel.JsonWebTokens
 * https://www.nuget.org/packages/Microsoft.IdentityModel.JsonWebTokens/6.8.0?_src=template
 */


/*
 * AWSSDK.S3
 * AWSSDK.SES
 */

namespace AwsSesSample
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private int messageCount = 0;
        private CognitoUser _cognitoUser = null;
        public MainWindow()
        {
            InitializeComponent();

            this.SendMessageButton.IsEnabled = false;
            this.RefreshButton.IsEnabled = false;
            
            this.UserPool.Text = ConfigData.UserPoolId;
            this.IdentityPool.Text = ConfigData.IdentityProviderName;
            

            this.UserName.Text = ConfigData.UserName;
            this.Password.Password = ConfigData.Password;

            this.MessageTextBox.Text = "This message body contains HTML formatting. It can, for example, contain links like this one: <a class=\"ulink\" href=\"http://docs.aws.amazon.com/ses/latest/DeveloperGuide\" target=\"_blank\">Amazon SES Developer Guide</a>.";
        }

        public CognitoUser User
        {
            get { return _cognitoUser; }
            set { _cognitoUser = value; }
        }

        //Get the OpenId token.
        public async Task<string> GetIdToken()
        {
            if (User != null && User.SessionTokens != null && User.SessionTokens.IsValid() == false)
            {
                //Get new Open Id and Access token by using the Refresh token.
                await RefreshTokens(User.Username, User.SessionTokens.RefreshToken);
            }
            return User.SessionTokens.IdToken;
        }

        //Get the Access token.
        public async Task<string> GetAccessToken()
        {
            if (User != null && User.SessionTokens != null && User.SessionTokens.IsValid() == false)
            {
                //Get new Open Id and Access token by using the Refresh token.
                await RefreshTokens(User.Username, User.SessionTokens.RefreshToken);
            }
            return User.SessionTokens.AccessToken;
        }

        //Get AWS Credentials from the Id Token.
        //These credentials are used to gain direct access to AWS Services
        public async Task<CognitoAWSCredentials> GetAuthenticatedCredentials()
        {
            CognitoAWSCredentials credentials = new CognitoAWSCredentials(
                ConfigData.IdentityPoolId, // Identity pool ID
                RegionEndpoint.EUWest1 // Region
            );

            //The Identity Provider in this case is the User Pool your user resides in.
            string idName = ConfigData.IdentityProviderName;
            //Get a valid OpenId token.
            string idToken = await GetIdToken();
            //Enrich the credential.
            credentials.AddLogin(idName, idToken);

            return credentials;
        }

        private async void Login_Click(object sender, RoutedEventArgs e)
        {
            string userName = this.UserName.Text;
            string password = this.Password.Password.ToString();

            if (userName != null && userName != string.Empty && password != null && password != string.Empty)
            {
                AuthFlowResponse authResponse = await AuthenticateWithSrpAsync(userName, password);

                if (User != null && User.SessionTokens != null)
                {
                    DisplayAccessToken(User.SessionTokens.AccessToken);
                    DisplayOpenIdToken(User.SessionTokens.IdToken);
                    this.SendMessageButton.IsEnabled = true;
                    this.RefreshButton.IsEnabled = true;
                }
            }
        }
        private async void Refresh_Click(object sender, RoutedEventArgs e)
        {
            string userName = this.UserName.Text;
            string refreshToken = null;

            if (userName != null && userName != string.Empty &&
                this.User != null && this.User.SessionTokens != null)
            {
                refreshToken = this.User.SessionTokens.RefreshToken;
                this.AccessTokenText.Text = string.Empty;
                this.OpenIdTokenText.Text = string.Empty;

                AuthFlowResponse authResponse = await RefreshTokens(userName, refreshToken);

                if (authResponse != null && authResponse.AuthenticationResult != null &&
                    User != null && User.SessionTokens != null)
                {
                    DisplayAccessToken(User.SessionTokens.AccessToken);
                    DisplayOpenIdToken(User.SessionTokens.IdToken);
                }
            }
        }

        private async void SendMessage_Click(object sender, RoutedEventArgs e)
        {
            this.SendMessageButton.IsEnabled = false;

            var credentials = await GetAuthenticatedCredentials();
            await SendMessage(credentials, RegionEndpoint.EUWest1);

            this.SendMessageButton.IsEnabled = true;
        }

        //Login
        private async Task<AuthFlowResponse> AuthenticateWithSrpAsync(string userName, string password)
        {
            AuthFlowResponse authResponse = null;
            var provider = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(), FallbackRegionFactory.GetRegionEndpoint());
            var userPool = new CognitoUserPool(ConfigData.UserPoolId, ConfigData.ClientId, provider);
            this.User = new CognitoUser(userName, ConfigData.ClientId, userPool, provider);

            try
            {
                authResponse = await this.User.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
                {
                    Password = password
                }).ConfigureAwait(false);

                if (authResponse.ChallengeName == ChallengeNameType.NEW_PASSWORD_REQUIRED)
                {
                    authResponse = await this.User.RespondToNewPasswordRequiredAsync(new RespondToNewPasswordRequiredRequest()
                    {
                        SessionID = authResponse.SessionID,
                        NewPassword = ""
                    });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return authResponse;
        }

        private async Task<AuthFlowResponse> RefreshTokens(string userName, string refreshToken)
        {
            AuthFlowResponse authResponse = null;

            this.User.SessionTokens = new CognitoUserSession(null, null, refreshToken, DateTime.Now, DateTime.Now.AddHours(1));

            try
            {
                InitiateRefreshTokenAuthRequest refreshRequest = new InitiateRefreshTokenAuthRequest()
                {
                    AuthFlowType = AuthFlowType.REFRESH_TOKEN_AUTH
                };

                authResponse = await User.StartWithRefreshTokenAuthAsync(refreshRequest).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                //TODO Show all exceptions!
                Console.WriteLine("!!!Re-login again!!!");
                Console.WriteLine(ex.Message);
            }
            return authResponse;
        }

        private async Task<bool> SendMessage(CognitoAWSCredentials creds, RegionEndpoint region)
        {
            bool result;
            try
            {
                AmazonSimpleEmailServiceClient client = new AmazonSimpleEmailServiceClient(creds, region);

                var mailRequest = new SendEmailRequest
                {
                    Destination = new Destination
                    {
                    /*    BccAddresses = new List<string>
                        {
                            "akrijten@gmail.com"
                        },
                        CcAddresses = new List<string> {
                            "krijtenb@gmail.com"
                        },*/
                        ToAddresses = new List<string> {
                            ToEMailTextBox.Text
                        }
                    },
                    Message = new Amazon.SimpleEmail.Model.Message
                    {
                        Body = new Body
                        {
                            Html = new Content {
                                Charset = "UTF-8",
                                Data = MessageTextBox.Text
                            },
                            Text = new Content {
                                Charset = "UTF-8",
                                Data = "This is the message body in text format."
                            }
                        },
                        Subject = new Content {
                            Charset = "UTF-8",
                            Data = SubjectTextBox.Text
                        }
                    },
                    ReplyToAddresses = new List<string> {
                        ReplyToEMailTextBox.Text
                    },
                    Source = "no-reply@hollandcasino.nl"
                };
                var response = await client.SendEmailAsync(mailRequest); ;

                string messageId = response.MessageId;

                result = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                result = false;
            }

            return result;
        }

        private void DisplayAccessToken(string accessToken)
        {
            if (accessToken != null &&
                accessToken != string.Empty)
            {
                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadToken(accessToken) as JwtSecurityToken;

                StringBuilder sb = new StringBuilder();

                foreach (var claim in token.Claims)
                {
                    sb.AppendFormat("{0}: {1}{2}", claim.Type, claim.Value, Environment.NewLine);
                }

                this.AccessTokenText.Text = sb.ToString();
            }
        }
        private void DisplayOpenIdToken(string idToken)
        {
            if (idToken != null &&
                idToken != string.Empty)
            {
                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadToken(idToken) as JwtSecurityToken;

                StringBuilder sb = new StringBuilder();

                foreach (var claim in token.Claims)
                {
                    sb.AppendFormat("{0}: {1}{2}", claim.Type, claim.Value, Environment.NewLine);
                }

                this.OpenIdTokenText.Text = sb.ToString();
            }
        }
    }
}
