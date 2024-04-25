export const magicLinkMailTemplate = (magicLink: string) => {
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
                        You recently requested to login to AuthOne platform.
                        Click the button below to proceed.
                      </p>
                      <a
                        style="
                          font-size: 16px;
                          line-height: 24px;
                          font-family: Arial, sans-serif;
                          background-color: #3182ce;
                          color: #fff;
                          border: none;
                          cursor: pointer;
                          padding: 12px 20px;
                          border-radius: 8px;
                          text-decoration: none;
                          margin: 12px 0;
                          display: inline-block;
                        "
                        href="${magicLink}"
                      >
                        Login to AuthOne
                      </a>
                      <p
                        style="
                          margin-top: 16px;
                          font-size: 16px;
                          line-height: 24px;
                          font-family: Arial, sans-serif;
                        "
                      >
                        This magic link is only valid for the next 5 minutes.
                      </p>
                      <p
                        style="
                          margin-top: 16px;
                          font-size: 16px;
                          line-height: 24px;
                          font-family: Arial, sans-serif;
                        "
                      >
                        If you did not request login, please ignore this email
                        or reply to let us know.
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
