# Guardián DMARC, SPF y DKIM

[![Auditoria Tecnica](https://img.shields.io/badge/TAVARDT-Seguridad%20Correo-5b3cf5.svg)](https://tools.tavardt.com/mx/verificador-dmarc-correo/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Auditoría de registros DNS de correo para prevención de suplantación, phishing y cumplimiento de las recomendaciones del INAI y la LFPDPPP en México.

Desarrollado y mantenido por la práctica de ciberdefensa de **TAVARDT** para organizaciones mexicanas.

***

## 1. Características y Capacidades de Verificación

Esta utilidad de terminal audita registros DNS de autenticación, postura anti-spoofing y claves criptográficas para organizaciones en México:

* **Aplicación de Política DMARC:** Inspección exhaustiva de directivas de imposición (reject, quarantine y none), política de subdominios (sp) y tasa de porcentaje (pct).
* **Auditoría de Registro SPF:** Validación de mecanismos de remitente autorizado, límites de búsquedas DNS y calificadores estrictos (-all frente a ~all).
* **Verificación de Firma DKIM:** Validación criptográfica de clave pública a través de selectores DNS definidos.
* **Telemetría Agregada y Forense:** Verificación de canales de reporte agregado (rua) para detectar incidentes de Business Email Compromise.
* **Cero Dependencias Externas:** Motor nativo de DNS-over-HTTPS (DoH) con respaldo automático mediante nslookup del sistema.

***

## 2. Línea Base de Autenticación y Matriz de Puntuación

<table>
  <thead>
    <tr>
      <th>Control de Autenticación</th>
      <th>Consulta DNS Objetivo</th>
      <th>Línea Base Recomendada</th>
      <th>Peso en Score</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Política DMARC (p)</strong></td>
      <td><code>_dmarc.&lt;dominio&gt;</code></td>
      <td><code>p=reject</code> (Rechazo inmediato de correos no autorizados)</td>
      <td>45 puntos</td>
    </tr>
    <tr>
      <td><strong>Reportes Agregados DMARC (rua)</strong></td>
      <td><code>_dmarc.&lt;dominio&gt;</code></td>
      <td>URI <code>mailto:</code> válida para telemetría agregada en XML</td>
      <td>10 puntos</td>
    </tr>
    <tr>
      <td><strong>Calificador Estricto SPF</strong></td>
      <td><code>&lt;dominio&gt;</code></td>
      <td><code>-all</code> (Fallo estricto para servidores no autorizados)</td>
      <td>30 puntos</td>
    </tr>
    <tr>
      <td><strong>Clave Pública DKIM</strong></td>
      <td><code>&lt;selector&gt;._domainkey.&lt;dominio&gt;</code></td>
      <td>Registro público válido (<code>v=DKIM1; p=...</code>)</td>
      <td>15 puntos</td>
    </tr>
    <tr>
      <td><strong>Umbral de Cumplimiento</strong></td>
      <td>Evaluación Consolidada</td>
      <td>Puntuación &gt;= 85 (Conforme - Defensa Estricta Impuesta)</td>
      <td>100 puntos Total</td>
    </tr>
  </tbody>
</table>

***

## 3. Instalación y Guía de Inicio Rápido

Requiere Python 3.8 o superior. Desarrollado exclusivamente con la biblioteca estándar de Python, sin dependencias externas.

```bash
git clone https://github.com/TAVARDT/dmarc-spf-guardian-mx.git
cd dmarc-spf-guardian-mx
python guardian.py ejemplo.com.mx
```

Ejecute la herramienta directamente mediante Python sin necesidad de instalar librerías externas:

```bash
python guardian.py ejemplo.com.mx -s default -j
```

* **Resolución DoH Nativa:** Emite consultas seguras DNS-over-HTTPS directamente a Cloudflare, eludiendo manipulaciones en resolvers locales.
* **Contingencia Automática:** Realiza fallback transparente al comando `nslookup` del sistema si la conexión HTTPS externa está restringida.
* **Exportación Estructurada en JSON:** Permite integración sencilla en plataformas de monitorización continua y validación mediante `-j`.

***

## 4. Preguntas Frecuentes (FAQ Técnico)

### 1. ¿Por qué resulta indispensable la política DMARC p=reject frente a p=none o p=quarantine?
La directiva p=none funciona únicamente en modo monitorización, permitiendo la entrega de correos suplantados en la bandeja de entrada. La política p=quarantine envía mensajes sospechosos a spam, mientras que p=reject bloquea y descarta el tráfico no autenticado de forma determinante.

### 2. ¿Qué riesgo operativo supone un registro SPF configurado con calificadores +all o ?all?
Un registro SPF finalizado en +all autoriza a cualquier host de internet a remitir correos en nombre de su dominio. Un calificador ?all adopta una postura neutra que anula las defensas perimetrales frente a suplantaciones de identidad.

### 3. ¿Cómo consulta guardian.py los registros DNS sin paquetes de terceros?
La herramienta emite solicitudes DNS-over-HTTPS hacia cloudflare-dns.com utilizando exclusivamente bibliotecas nativas de Python. Si la conexión HTTPS externa se ve restringida, ejecuta de forma automática el comando nativo nslookup del sistema operativo.

### 4. ¿Cuál es la relevancia de la etiqueta rua en el registro DMARC?
El parámetro rua especifica los buzones donde se reciben informes agregados diarios en XML enviados por los servidores de correo receptores. Esta telemetría permite auditar direcciones IP emisoras, tasas de alineación y vectores de suplantación dirigidos.

### 5. ¿Cómo puede integrarse este monitor de seguridad de correo en flujos de CI/CD?
Al ejecutar guardian.py con el parámetro -j, la herramienta genera una salida JSON determinista que contiene la puntuación y las alertas detectadas. Los pipelines de despliegue continuo pueden procesar esta salida y bloquear cambios si la calificación cae por debajo de 85 puntos.

***

## 5. Consultoría y Protección de Correo en México

Para arquitectura de ciberseguridad avanzada, modelado de amenazas y preparación ante incidentes en Ciudad de México, Monterrey o Guadalajara, contacte con **TAVARDT**.

***

## Enlaces Útiles

* **Portal Corporativo:** https://ag.tavardt.com/mx/
* **Suite de Diagnóstico:** https://tools.tavardt.com/mx/
* **Contacto Técnico:** https://ag.tavardt.com/mx/contacto/

***

### Licencia
Distribuido bajo la Licencia MIT.

***

© 2026 TAVARDT. Todos os direitos reservados.
