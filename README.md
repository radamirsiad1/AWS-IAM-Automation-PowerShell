# AWS-IAM-Automation-PowerShell
Automated AWS IAM user provisioning and deprovisioning using PowerShell (macOS compatible). Includes CSV-based input, secure cleanup logic for IAM entities, and a step-by-step guide for setting up IAM permissions, JSON policy configuration, and automation execution.
# 🧩 Automating AWS IAM User Provisioning & Deprovisioning Using PowerShell

This repository demonstrates a fully automated solution for **AWS Identity and Access Management (IAM)** user lifecycle management using **PowerShell**.  
It provisions new IAM users, assigns them to departmental groups, and safely deprovisions users by removing all related IAM entities before deletion.

---

## 📄 Documentation

A complete step-by-step PDF guide (with screenshots) is included below:

📘 [Provisioning & Deprovisioning AWS User Groups Using PowerShell Scripts (PDF)](./Provisioning%20%26%20Deprovisioning%20AWS%20user%20groups%20using%20PowerShell%20scripts.pdf)

---

## 🧰 Repository Structure

| File | Description |
|------|--------------|
| [`provisioning.ps1`](./provisioning.ps1) | Main PowerShell automation script for creating and deleting IAM users. |
| [`users.csv`](./users.csv) | Sample CSV file defining user accounts, departments, and actions (Create/Delete). |
| [`IAMUserProvisionPolicy.txt`](./IAMUserProvisionPolicy.txt) | JSON IAM policy granting least-privilege access for provisioning automation. |
| [`Provisioning & Deprovisioning AWS user groups using PowerShell scripts.pdf`](./Provisioning%20%26%20Deprovisioning%20AWS%20user%20groups%20using%20PowerShell%20scripts.pdf) | Full documentation guide with instructions and screenshots. |

---

## ⚙️ How It Works

1. **Input**: Reads `users.csv` containing user info and desired action.  
2. **Provisioning**:
   - Creates IAM users and departmental groups.
   - Assigns tags for Department, CreatedBy, and Name fields.
   - Optionally creates login profiles for console access.
3. **Deprovisioning**:
   - Removes users from all groups.
   - Detaches all IAM policies and deletes access keys, SSH keys, certificates, and MFA devices.
   - Deletes the IAM user safely, ensuring no linked resources remain.
4. **Logging**:
   - Creates a transcript log in `~/Downloads/provisioning_log.txt` for audit tracking.

---

## 🧾 Example CSV Format

```csv
FirstName,LastName,UserName,Department,Action
Alice,Johnson,alice.johnson,Finance,Create
Bob,Miller,bob.miller,IT,Create
Eve,Smith,eve.smith,HR,Delete
