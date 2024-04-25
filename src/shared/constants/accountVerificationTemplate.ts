export const accountVerificationTemplate = (code: string) => {
  return `
<!DOCTYPE html>
<html
  lang="en"
  xmlns="http://www.w3.org/1999/xhtml"
  xmlns:o="urn:schemas-microsoft-com:office:office"
>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <meta name="x-apple-disable-message-reformatting" />
    <title></title>
    <!--[if mso]>
      <noscript>
        <xml>
          <o:OfficeDocumentSettings>
            <o:PixelsPerInch>96</o:PixelsPerInch>
          </o:OfficeDocumentSettings>
        </xml>
      </noscript>
    <![endif]-->
    <style>
      table,
      td,
      div,
      h1,
      p {
        font-family: Arial, sans-serif;
      }
    </style>
  </head>
  <body style="margin: 0; padding: 0">
    <table
      role="presentation"
      style="
        width: 100%;
        border-collapse: collapse;
        border: 0;
        border-spacing: 0;
        background: #f2f4fa;
      "
    >
      <tr>
        <td align="center" style="padding: 0">
          <table
            role="presentation"
            style="width: 600px; border-collapse: collapse; text-align: left"
          >
            <tr>
              <td style="padding: 28px 0">
                <a href="/"> </a>
              </td>
            </tr>
            <tr>
              <td
                style="
                  padding: 36px;
                  padding-bottom: 16px;
                  border-radius: 10px;
                  background-color: #ffffff;
                  box-shadow: rgba(0, 0, 0, 0.1) 0px 2px 2px 0px;
                "
              >
                <table
                  role="presentation"
                  style="
                    width: 100%;
                    border-collapse: collapse;
                    border: 0;
                    border-spacing: 0;
                  "
                >
                  <tr>
                    <td style="color: #171923">
                      <p
                        style="
                          margin: 0;
                          font-size: 16px;
                          line-height: 24px;
                          font-family: Arial, sans-serif;
                        "
                      >
                        Hi 👋
                      </p>
                      <p
                        style="
                          margin-top: 16px;
                          font-size: 16px;
                          line-height: 24px;
                          font-family: Arial, sans-serif;
                        "
                      >
                        Welcome to AuthOne! We're excited to have you on board.
                        To complete your account setup, please use the
                        verification code below:
                      </p>
                      <p>
                        <strong
                          style="
                            font-size: 28px;
                            line-height: 32px;
                            font-family: Arial, sans-serif;
                            padding: 12px 0;
                            text-align: center;
                            display: inline-block;
                            width: 100%;
                            letter-spacing: 8px;
                          "
                        >
                          ${code}
                        </strong>
                      </p>
                      <p
                        style="
                          margin-top: 16px;
                          font-size: 16px;
                          line-height: 24px;
                          font-family: Arial, sans-serif;
                        "
                      >
                        Please enter this code in the verification section of
                        your account settings to activate your account.
                      </p>
                      <p
                        style="
                          margin-top: 16px;
                          font-size: 16px;
                          line-height: 24px;
                          font-family: Arial, sans-serif;
                        "
                      >
                        If you didn't sign up for AuthOne, you can ignore this
                        email.
                      </p>
                      <p
                        style="
                          margin-top: 16px;
                          font-size: 16px;
                          line-height: 24px;
                          font-family: Arial, sans-serif;
                        "
                      >
                        Best Regards,<br />
                        Huy Nguyen Kim
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="padding: 36px 0; color: #718096">
                <p
                  style="
                    margin: 0;
                    font-size: 16px;
                    line-height: 16px;
                    font-family: Arial, sans-serif;
                  "
                >
                  AuthOne - Made with ❤️ by kimhuy011199
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
`;
};
