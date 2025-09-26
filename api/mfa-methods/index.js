const fetch = require("node-fetch");
const querystring = require("querystring");

module.exports = async function (context, req) {
  const upn = req.query.upn;

  if (!upn) {
    context.res = {
      status: 400,
      body: { error: "Missing required query parameter: upn" }
    };
    return;
  }

  try {
    // Token request to Microsoft identity platform
    const tokenResponse = await fetch("https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: querystring.stringify({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        scope: "https://graph.microsoft.com/.default",
        grant_type: "client_credentials"
      })
    });

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // Get all auth methods
    const methodsResponse = await fetch(`https://graph.microsoft.com/v1.0/users/${upn}/authentication/methods`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const methodsData = await methodsResponse.json();

    // Get default method
    const defaultResponse = await fetch(`https://graph.microsoft.com/v1.0/users/${upn}/authentication/signInPreferences`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const defaultData = await defaultResponse.json();

    const friendlyMap = {
      "push": "Microsoft Authenticator app (push notification)",
      "microsoftAuthenticator": "Microsoft Authenticator app",
      "fido2": "FIDO2 Security Key",
      "windowsHelloForBusiness": "Windows Hello for Business",
      "mobilePhone": "Phone (mobile, SMS)",
      "voiceMobile": "Phone (mobile, voice call)",
      "voiceOffice": "Phone (office, voice call)",
      "softwareOath": "Software OATH Token"
    };

    const preferredDefault = defaultData?.userPreferredMethodForSecondaryAuthentication;
    const friendlyDefault = preferredDefault ? (friendlyMap[preferredDefault] || preferredDefault) : null;

    const methods = (methodsData.value || []).map(m => {
      if (m["@odata.type"] === "#microsoft.graph.fido2AuthenticationMethod") {
        return { type: "FIDO2 Security Key", model: m.model, isDefault: false };
      } else if (m["@odata.type"] === "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod") {
        return { type: "Windows Hello for Business", device: m.displayName, keyStrength: m.keyStrength };
      } else if (m["@odata.type"] === "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod") {
        return { type: "Microsoft Authenticator", device: m.displayName, isDefault: false };
      } else if (m["@odata.type"] === "#microsoft.graph.phoneAuthenticationMethod") {
        return { type: "Phone", number: m.phoneNumber, phoneType: m.phoneType, smsSignInEnabled: m.smsSignInEnabled, isDefault: false };
      } else if (m["@odata.type"] === "#microsoft.graph.softwareOathAuthenticationMethod") {
        return { type: "Software OATH Token", secretKey: m.secretKey, isDefault: false };
      } else {
        return { type: m["@odata.type"], raw: m };
      }
    }).filter(m => !m.type.startsWith("#microsoft.graph.emailAuthenticationMethod"));

    context.res = {
      status: 200,
      body: {
        upn,
        preferredDefaultFromGraph: preferredDefault
          ? { raw: preferredDefault, friendly: friendlyDefault }
          : null,
        methods
      }
    };

  } catch (err) {
    context.log.error("Error fetching MFA methods:", err);
    context.res = {
      status: 500,
      body: { error: "Failed to fetch MFA methods", details: err.message }
    };
  }
};
