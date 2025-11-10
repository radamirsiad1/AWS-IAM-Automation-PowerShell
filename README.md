# AWS-IAM-Automation-PowerShell
Automated AWS IAM user provisioning and deprovisioning using PowerShell (macOS compatible). Includes CSV-based input, secure cleanup logic for IAM entities, and a step-by-step guide for setting up IAM permissions, JSON policy configuration, and automation execution.
# 🧩 AWS IAM Automation using PowerShell

This project demonstrates how to automate **user provisioning and deprovisioning** in AWS Identity and Access Management (IAM) using **PowerShell scripts** and a **CSV-driven approach**.  
The automation simulates real-world IAM workflows such as user creation, group assignment, and removal, providing a practical understanding of how AWS IAM can be managed programmatically.

---

## 📘 Project Overview

The project automates:
- Creating and deleting IAM users in AWS.
- Assigning users to department-based groups (e.g., Finance, IT, HR).
- Reading all user actions from a CSV file.
- Logging actions and results for audit tracking.

This was tested successfully using **PowerShell on macOS** and the **AWS.Tools** PowerShell modules.

---

## 🛠️ Technologies Used

- **AWS IAM (Identity and Access Management)**
- **PowerShell 7+**
- **AWS.Tools.Common** and **AWS.Tools.IdentityManagement** modules
- **CSV input file** for user provisioning actions
- **JSON IAM policy** for permission management

---

## 📂 Project Files

| File Name | Description |
|------------|-------------|
| [`provisioning.ps1`](./provisioning.ps1) | Main PowerShell script that provisions and deprovisions IAM users based on CSV input. |
| [`users.csv`](./users.csv) | Contains user data (first name, last name, username, department, and action). |
| [`IAMUserProvisionPolicy.txt`](./IAMUserProvisionPolicy.txt) | IAM policy allowing PowerShell to perform create/delete actions in AWS. |
| [📘 **Project Guide (PDF)**](./Provisioning%20%26%20Deprovisioning%20AWS%20user%20groups%20using%20PowerShell%20scripts.pdf) | Full documentation and screenshots on how to replicate this setup. |

---
