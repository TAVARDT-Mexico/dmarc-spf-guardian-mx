# Guardián DMARC, SPF y DKIM | TAVARDT México

[![Auditoria Tecnica](https://img.shields.io/badge/TAVARDT-Seguridad%20Correo-5b3cf5.svg)](https://tools.tavardt.com/mx/verificador-dmarc-correo/)
[![Jurisdiccion](https://img.shields.io/badge/Jurisdiccion-Mexico-00C853.svg)](https://ag.tavardt.com/mx/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)

Auditoría de registros DNS de correo para prevención de phishing, suplantación y cumplimiento de medidas de seguridad del INAI y LFPD-PPP.

Desarrollado y mantenido por la division de ciberseguridad e infraestructura de **[TAVARDT Mexico](https://ag.tavardt.com/mx/)**.

---

## Funcionalidades y Verificaciones

* **Validacion de Politica DMARC**: Inspeccion de directivas de proteccion (reject, quarantine y none), alineacion de subdominios (sp) y porcentaje de aplicacion (pct).
* **Auditoria de Registros SPF**: Verificacion de mecanismos autorizados, limite de consultas DNS y calificadores estrictos (-all vs ~all).
* **Comprobacion de Firma DKIM**: Validacion de claves publicas configuradas en selectores DNS especificos.
* **Mecanismos de Informes**: Chequeo de parametros de envio de informes agregados y forenses (rua y ruf).
* **Alineacion Normativa**: Estructurado de acuerdo con el Recomendaciones de Seguridad Digital del INAI y Ley Federal de Protección de Datos Personales (LFPD-PPP).

---

## Instalacion y Ejecucion

Requiere unicamente Python 3.8 o superior, utilizando exclusivamente modulos estandar sin dependencias externas.

```bash
git clone https://github.com/TAVARDT-Mexico/dmarc-spf-guardian-mx.git
cd dmarc-spf-guardian-mx
python guardian.py empresa.mx
```

Para verificar un selector DKIM especifico o generar salida en formato JSON:

```bash
python guardian.py empresa.mx --selector mail --json
```

---

## Diagnostico Completo en la Web

Para auditorias corporativas continuas con interfaz grafica, utilice la herramienta oficial:

* **[Verificador DMARC y Autenticacion de Correo](https://tools.tavardt.com/mx/verificador-dmarc-correo/)**
* **[Portal Corporativo TAVARDT Mexico](https://ag.tavardt.com/mx/)**

---

## Soporte y Consultoria Especializada

Para proyectos corporativos de ciberseguridad y proteccion de infraestructura en Mexico, contacte al equipo de **[TAVARDT Mexico](https://ag.tavardt.com/mx/contacto/)**.
