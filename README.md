# Digital_Signatures_WPF_App
**implementing digital signatures in a WPF application(Unsigned Exe)**


---

# Why Digital Signatures required in a WPF Application
Digital signatures in a WPF application are important for several reasons:

### 1. **Authenticity**

- **Proves Identity:** Digital signatures verify the identity of the software publisher. When you sign your application with a digital certificate, you provide assurance to users that the application comes from a trusted source and has not been tampered with.
- **Trust Building:** Users are more likely to trust and install applications that are digitally signed because it demonstrates that the software publisher is reputable and that the software has not been altered since it was signed.

### 2. **Integrity**

- **Prevents Tampering:** A digital signature ensures that the application has not been modified or corrupted since it was signed. If any changes are made to the application after it is signed, the digital signature will no longer be valid, alerting users to potential issues.
- **Protects from Malware:** By using digital signatures, you reduce the risk of malicious tampering with your application. A valid signature confirms that the software is exactly as intended by the publisher.

### 3. **Compliance**

- **Security Policies:** Many operating systems and security policies require software to be signed to be installed or executed, especially in enterprise environments. Digital signatures help meet these compliance requirements.
- **Regulatory Requirements:** Certain industries and regulatory frameworks mandate the use of digital signatures to ensure software security and integrity.

### 4. **User Experience**

- **Reduces Warnings:** Signed applications typically avoid security warnings and prompts that unsigned applications might trigger. This improves the installation experience and reduces user anxiety about potential security risks.
- **Improves Credibility:** A signed application can enhance the credibility of your software, making it appear more professional and trustworthy.

### 5. **Timestamping**

- **Provides Proof of Signing Time:** Digital signatures can include a timestamp, which indicates when the application was signed. This is important for maintaining the validity of the signature over time, even if the certificate itself expires.

### 6. **Software Distribution**

- **Facilitates Updates:** Digital signatures help ensure that software updates are authentic and have not been altered during distribution. This is crucial for maintaining the integrity of software updates and patches.
- **Supports Automatic Updates:** Many software update mechanisms check for valid digital signatures before applying updates, helping to ensure that only authorized and unaltered updates are installed.

In summary, digital signatures play a crucial role in verifying the authenticity and integrity of a WPF application, complying with security policies, enhancing user trust, and facilitating secure software distribution.



# Implementing Digital Signatures in a WPF Application

## 1. Creating a Self-Signed Code Signing Certificate

### 1.1 Using PowerShell

1. **Open PowerShell as Administrator:**
   - Right-click on the PowerShell icon and select **Run as administrator**.

2. **Run the PowerShell Command:**
   - Execute the following command to create a new self-signed code signing certificate:
     ```powershell
     New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=MyCodeSigningCert" -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\My"
     ```
   - Example:
     ```powershell
     New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=MyCompany" -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\My"
     ```
   - Note: `CN` should ideally be the company name, e.g., `MyCompany`.

### 1.2 Exporting the Certificate to a PFX File

#### Manually(Prefered)

1. **Locate the Newly Created Certificate:**
   - Open the Certificate Manager (`certmgr.msc`) and navigate to **Personal** > **Certificates**.
   - Find the certificate with the subject name `CN=TrafikViewApplication_Certificate`.

2. **Export the Certificate:**
   - Right-click on the certificate, select **All Tasks** > **Export**.
   - Follow the Certificate Export Wizard:
     - Select **Yes, export the private key**.
     - Choose the **PFX** option.
     - Check **Include all certificates in the certification path if possible** and **Export all extended properties**.
     - Set a password for the PFX file.
     - write the File name e.g., `MyCompany`.
     - Specify a file path to save the PFX file, e.g., `C:\path\to\MyCompany.pfx`.

#### Using PowerShell Script

1. **PowerShell Script for Creating and Exporting Certificate:**
   ```powershell
   # Define certificate parameters
   $certSubject = "CN=MyCodeSigningCert"
   $certStoreLocation = "Cert:\CurrentUser\My"
   $pfxFilePath = "C:\path\to\MyCompany.pfx"
   $pfxPassword = "your_password"

   # Create the self-signed code signing certificate
   $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $certSubject -KeyExportPolicy Exportable -CertStoreLocation $certStoreLocation

   # Export the certificate to a PFX file
   $securePfxPassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
   Export-PfxCertificate -Cert $cert -FilePath $pfxFilePath -Password $securePfxPassword
   ```
   - Example:
     ```powershell
     # Define certificate parameters
     $certSubject = "CN=TrafikViewApplication_Certificate"
     $certStoreLocation = "Cert:\CurrentUser\My"
     $pfxFilePath = "C:\path\to\MyCompany.pfx"
     $pfxPassword = "your_password"

     # Locate the certificate
     $cert = Get-ChildItem -Path $certStoreLocation | Where-Object { $_.Subject -eq $certSubject }

     # Export the certificate to a PFX file
     $securePfxPassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
     Export-PfxCertificate -Cert $cert -FilePath $pfxFilePath -Password $securePfxPassword
     ```

2. **Copy the PFX File:**
   - Move the PFX file (e.g., `C:\path\to\MyCompany.pfx`) to your bin/debug folder for use in your project.

## 2. Signing the Executable with the New Certificate

### 2.1 Download Windows SDK

1. **Download Windows SDK:**
   - Visit the [Windows SDK download page](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) and download the SDK.

2. **Set Environment Path:**
   - Set the environment path for the Windows SDK tools (e.g., `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64`). Adjust according to your version.

### 2.2 Use Signtool to Sign Your Executable

1. **Open Command Prompt as Administrator:**
   - Run Command Prompt with administrative privileges.

2. **Sign the Executable:**
   - Use the `signtool` command to sign your executable:
     ```cmd
     signtool sign /f "C:\path\to\MyCompany.pfx" /p "your_password" /fd SHA256 /t "http://timestamp.digicert.com" "DriveName:\pathto\bin\Debug\Myapp.exe"
     ```
   - Replace `C:\path\to\MyCompany.pfx` with the path to your exported PFX file and `your_password` with the password set during export.
```cmd
Parameters:
/f "DriveName:\pathto\MyCompany.pfx": Specifies the path to your code signing certificate. Replace DriveName:\pathto\MyCompany.pfx with the actual path to your .pfx file.
/p "YourPassword": Provides the password for your certificate. Replace YourPassword with the actual password for your certificate.
/fd SHA256: Specifies the digest algorithm to use. SHA256 is recommended for strong security.
/t "http://timestamp.digicert.com": Uses a timestamp server to ensure the validity of the signature even after the certificate expires. You can use this URL or replace it with another valid timestamp server URL.
"DriveName:\pathto\bin\Debug\Myapp.exe": Specifies the path to the executable file you want to sign. Replace DriveName:\pathto\bin\Debug\Myapp.exe with the actual path to your executable.
```
## 3. Verifying the Digital Signature

### 3.1 Using Windows File Explorer

1. **Locate Your Executable:**
   - Navigate to the directory where your signed executable (`Myapp.exe`) is located.

2. **View File Properties:**
   - Right-click on `Myapp.exe` and select **Properties**.

3. **View Digital Signatures:**
   - In the **Properties** window, go to the **Digital Signatures** tab.

4. **Verify Signature Details:**
   - Select the digital signature entry associated with your certificate and click **Details**.
   - Check:
     - **Issuer** and **Subject** fields match your certificate details.
     - **Timestamp** confirms when the file was signed.
     - **Digest algorithm** used (e.g., SHA256).

5. **Check Digital Signature Status:**
   - Ensure the status shows **This digital signature is OK**.

### 3.2 Using Signtool Command Line

1. **Open Command Prompt:**
   - Run Command Prompt as Administrator.

2. **Verify the Digital Signature:**
   - Use the `signtool` command to verify the digital signature:
     ```cmd
     signtool verify /pa /v "DriveName:\pathto\bin\Debug\Myapp.exe"
     ```
   - **/pa** checks for a valid signature chain to a trusted root.
   - **/v** provides verbose output.
3. **you can also use sigcheck exe to check verify status**
   - download the [sigcheck exe](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) & setup the environment variable path
   - open cmd command
   ```cmd
     sigcheck.exe DriveName:\pathto\bin\Debug\Myapp.exe
   ```
     
## 4. Resolving Certificate Trust Issues


       **Example**
         e:\development\Myapp.exe:
        Verified:       A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.
        Link date:      13:09 18/07/2024
        Publisher:      MyCompany
        Company:        n/a
        Description:    Myapp
        Product:        Myapp
        Prod version:   1.0.2.1
        File version:   1.0.2.1
        MachineType:    64-bit

### 4.1 Manually Install the Root Certificate

1. **Export the Root Certificate:**
   - Open Certificate Manager (`certmgr.msc`).
   - Navigate to **Certificates - Current User** > **Personal**.
   - Right-click on your certificate and select **All Tasks** > **Export...**.
- Follow the Certificate Export Wizard:
     - Select **No, do not export the private key**.
     - Choose **Base-64 encoded X.509 (.CER)** format and save it as a `.cer` file.
     - write the File name e.g., `TrafikViewApplication_Certificate`.
     -Specify a file path to save the CER file, e.g., `C:\path\to\MyCompany.cer`. (path vary after export showing there path name)

2. **Install the Root Certificate:**
   - Open Certificate Manager (`certmgr.msc`).
   - Navigate to **Certificates - Current User** > **Trusted Root Certification Authorities** > **Certificates**.
   - Right-click on **Certificates** and select **All Tasks** > **Import...**.
   - Browse to the `.cer` file and follow the wizard to install it in **Trusted Root Certification Authorities**.

3. **Verify Installation:**
   - Reopen `certmgr.msc` and confirm the root certificate is listed under **Trusted Root Certification Authorities**.

### 4.2 Re-verify the Digital Signature

1. **Re-sign the Executable:**
   - Use the `signtool` command again to re-sign the executable:
   -Check the Sign the Executable again as described in section 2.2.
     ```cmd
     signtool sign /f "C:\path\to\MyCompany.pfx" /p "your_password" /fd SHA256 /t "http://timestamp.digicert.com" "DriveName:\pathto\bin\Debug\Myapp.exe"
     ```

2. **Re-verify using File Explorer or Signtool:**
   - Check the signature status again as described in Section 3.
     
3. **you can also use sigcheck exe to check verify status**
   - download the sigcheck exe (https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck)  & setup the environment variable path
   - open cmd command
     ```cmd
     sigcheck.exe DriveName:\pathto\bin\Debug\Myapp.exe
     ```
---
 output:-
  e:\02.development\debug\Myapp.exe:
        Verified:       Signed
        Signing date:   16:39 18/07/2024
        Publisher:      MyCompany
        Company:        n/a
        Description:    Myapp
        Product:        Myapp
        Prod version:   1.0.2.1
        File version:   1.0.2.1
        MachineType:    64-bit , finally verified signed successfully

### 5 Installing the Certificate on the Machine
    Follow the section 2. i.e. Signing the Executable with the New Certificate & section 3. Verifying the Digital Signature & section 4. Resolving Certificate Trust Issues


This documentation provides a clear guide for creating, exporting, signing, and verifying digital signatures for your WPF application.

Author: [Bhakta Charan Rout](https://github.com/BhaktaRout038)
