# nmap_symbVenum

## 📌 Description  
This script converts **Nmap XML results** into a clear and organized **Excel report**.  

The report includes only hosts with **open ports**, creating one sheet per IP, and provides details such as:  
- IP address  
- Open ports, protocols, and services  
- Detected operating system (if available)  
- Uptime and traceroute (if available)  

This tool helps you **clean and simplify the results** of Zenmap/Nmap, making it especially useful for **large scans**.  
It delivers **clear, structured results** ready for **pentesting documentation** or **vulnerability management**.  

---

## ⚙️ Requirements  
Make sure you have Python 3 and the following libraries installed:  

```bash
pip install pandas openpyxl

