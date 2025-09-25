module.exports = async function (context, req) {
  const upn = req.query.upn || (req.body && req.body.upn);

  if (!upn) {
    context.res = {
      status: 400,
      body: { error: "Missing UPN query parameter" }
    };
    return;
  }

  // Mock data for now
  context.res = {
    headers: { "Content-Type": "application/json" },
    body: {
      methods: [
        {
          id: "1",
          type: "Microsoft Authenticator",
          isDefault: true,
          lastUsed: "2025-09-10T11:32:00Z",
          isEnabled: true,
          strength: "strong"
        },
        {
          id: "2",
          type: "Phone (SMS)",
          phoneNumber: "+44••••1234",
          lastUsed: "2025-09-12T08:03:21Z",
          isEnabled: true,
          strength: "medium"
        }
      ]
    }
  };
};

