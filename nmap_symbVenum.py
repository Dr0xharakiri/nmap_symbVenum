import xml.etree.ElementTree as ET
import pandas as pd
import os

# === ARTE ASCII ===
print(r"""
                     __,-~~/~    `---.
                   _/_,---(      ,    )
               __ /        <    /   )  \___
- ------===;;;'====------------------===;;;===----- -  -
                  \/  ~"~"~"~"~"~\~"~)~"/
                  (_ (   \  (     >    \)
                   \_( _ <         >_>'
                      ~ `-i' ::>|--"
                          I;|.|.|
                         <|i::|i|`.
                        (` ^'"`-' ")
""")
print("💻 Script extendido de análisis Nmap XML → Excel por IP (solo IPs con puertos abiertos)\n")

# === ENTRADAS INTERACTIVAS ===
xml_file = input("🗂️  Ingresa la ruta del archivo XML de Nmap: ").strip()
if not os.path.isfile(xml_file):
    print("❌ El archivo especificado no existe.")
    exit(1)

output_dir = input("📁 Ingresa la carpeta donde quieres guardar el archivo Excel: ").strip()
os.makedirs(output_dir, exist_ok=True)

nombre_excel = input("📝 Ingresa el nombre del archivo Excel de salida (ej. reporte_completo.xlsx): ").strip()
if not nombre_excel.endswith(".xlsx"):
    nombre_excel += ".xlsx"
ruta_completa_excel = os.path.join(output_dir, nombre_excel)

# === PARSEO XML ===
tree = ET.parse(xml_file)
root = tree.getroot()

# === PREPARAR HOJAS POR HOST CON PUERTOS ABIERTOS ===
host_sheets = {}

for host in root.findall("host"):
    ports = host.findall(".//port")
    if not ports:
        continue  # Saltar host si no tiene puertos

    ip_elem = host.find("address")
    ip_address = ip_elem.attrib.get("addr", "Desconocido") if ip_elem is not None else "Desconocido"

    # Sistema operativo
    os_info = "No detectado"
    osmatch = host.find(".//os/osmatch")
    if osmatch is not None:
        os_info = osmatch.attrib.get("name", "No detectado")

    # Uptime
    uptime_elem = host.find(".//uptime")
    uptime = uptime_elem.attrib.get("lastboot", "") if uptime_elem is not None else ""

    # Traceroute
    trace = host.find(".//trace")
    hops = []
    if trace is not None:
        for hop in trace.findall("hop"):
            ttl = hop.attrib.get("ttl", "")
            rtt = hop.attrib.get("rtt", "")
            ip = hop.attrib.get("ipaddr", "")
            hops.append(f"TTL: {ttl} - IP: {ip} - RTT: {rtt}ms")
    traceroute = " | ".join(hops)

    # Scripts NSE
    nse_results = []
    for script in host.findall(".//hostscript/script"):
        nse_results.append(f"{script.attrib.get('id', '')}: {script.attrib.get('output', '')}")
    nse_output = " | ".join(nse_results)

    # === EXTRACCIÓN DE PUERTOS Y SERVICIOS ===
    data = []

    for port in ports:
        port_id = port.attrib.get("portid")
        protocol = port.attrib.get("protocol")
        state = port.find("state").attrib.get("state")

        if state != "open":
            continue  # Solo considerar puertos abiertos

        service = port.find("service")
        service_name = service.attrib.get("name", "") if service is not None else ""
        product = service.attrib.get("product", "") if service is not None else ""
        version = service.attrib.get("version", "") if service is not None else ""
        detail = f"{service_name} {product} {version}".strip()

        # Certificados SSL si existen
        ssl_info = []
        for script in port.findall("script"):
            if "ssl-cert" in script.attrib.get("id", ""):
                ssl_info.append(script.attrib.get("output", ""))
        ssl_output = " | ".join(ssl_info) if ssl_info else "N/A"

        data.append({
            "Puerto": port_id,
            "Protocolo": protocol,
            "Estado": state,
            "Detalle": detail,
            "SO Detectado": os_info,
            "Último arranque": uptime,
            "Traceroute": traceroute,
            "SSL": ssl_output,
            "Scripts NSE": nse_output
        })

    if data:  # Solo guardar si hay datos (al menos un puerto abierto)
        df_host = pd.DataFrame(data)
        host_sheets[ip_address] = df_host

# === GUARDAR ARCHIVO EXCEL CON MULTI-HOJA ===
if host_sheets:
    with pd.ExcelWriter(ruta_completa_excel, engine='xlsxwriter') as writer:
        for ip, df in host_sheets.items():
            sheet_name = ip.replace(".", "_")[:31]  # Excel limita el nombre a 31 caracteres
            df.to_excel(writer, sheet_name=sheet_name, index=False)
    print(f"\n✅ Reporte generado correctamente en: {ruta_completa_excel}")
else:
    print("⚠️ No se encontraron hosts con puertos abiertos.")
