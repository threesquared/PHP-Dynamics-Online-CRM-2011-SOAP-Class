# PHP Dynamics Online CRM 2011 SOAP Class

This class is to enable you to connect to Microsoft Dynamics 2011 online cloud hosted CRM service with PHP via SOAP.

## Usage

You need to pass four parameters to the class:

- Your Live Email address
- Your Live password
- Your CRM url
- The debug level [optional]

```php
$dynamicsClient = new dynamicsClient('email','password','orgname.crm4.dynamics.com',1);
```

If the debug mode is set to 1 then all requests and reponse data will be printed.

**Please note I have been told Microsoft might have updated their authentication method.**
