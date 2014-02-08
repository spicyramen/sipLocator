from twilio.rest import TwilioRestClient

# Your Account Sid and Auth Token from twilio.com/user/account
account_sid = "AC433e7b0bec93dc5996e4fb80b1e56eec"
auth_token  = "9cc9267fe09dab362d3be160f711a09d"
client = TwilioRestClient(account_sid, auth_token)
 
message = client.sms.messages.create(body="Jenny please?! I love you <3",
    to="+14082186575",    # Replace with your phone number
    from_="++1415-795-2944") # Replace with your Twilio number
print message.sid