# QoriKey 🔐
> Microservicio de Custodia Criptográfica y Desencriptación Distribuida para Votación Blockchain.

**QoriKey** resuelve el problema del **Punto Único de Fallo (Single Point of Failure - SPOF)** en la custodia de llaves criptográficas de sistemas electorales descentralizados. Implementa el **Esquema de Secreto Compartido de Shamir (SSS)** con un umbral $(k=3, n=5)$ sobre un campo primo finito $\mathbb{F}_p$.

---

## 🏛️ Modelo de Custodia Institucional

Durante la ceremonia criptográfica inicial, la llave privada de desencriptación homomórfica de Paillier (utilizada para descifrar el escrutinio total de votos de *QoriCore*) se divide en **5 fragmentos independientes**:

| ID ($x$) | Institución Custodia | Rol en el Proceso Electoral |
|---|---|---|
| `1` | **ONPE** | Autoridad técnica de organización y ejecución electoral |
| `2` | **JNE** | Órgano supremo de justicia y fiscalización electoral |
| `3` | **USS** | Entidad académica y auditora técnica independiente |
| `4` | **Veedor** | Misión de observación internacional y sociedad civil |
| `5` | **RENIEC** | Registro electoral e identificación biométrica |

### Propiedades de Seguridad:
- **Tolerancia a Faltas (Disponibilidad):** Hasta $2$ instituciones pueden estar ausentes o fuera de línea sin impedir la publicación del escrutinio final.
- **Resistencia a Colusión (Confidencialidad):** Cualquier coalición de $1$ o $2$ custodios maliciosos obtiene **cero información** sobre la llave privada original ($H(S \mid S_1, S_2) = H(S)$).
- **Umbral Estricto ($k=3$):** Se requiere el consenso activo de al menos $3$ custodios para reconstruir la llave mediante Interpolación de Lagrange en $x=0$.

---

## 📐 Fundamento Matemático

El microservicio opera sobre el campo primo $\mathbb{F}_p$ de 2048 bits estipulado en **RFC 3526 (MODP Group 14)**:

$$p = 2^{2048} - 2^{1984} - 1 + 2^{64} \cdot \left(\lfloor 2^{1918} \pi \rfloor + 124476\right)$$

1. **Generación Polinomial:**
   $$P(x) = \left(S + a_1 x + a_2 x^2\right) \pmod p$$
   donde $S$ es la llave privada, y $a_1, a_2 \in_R \mathbb{F}_p$ son coeficientes aleatorios generados de forma criptográficamente segura (`secrets`).

2. **Reconstrucción de Lagrange en $x=0$:**
   Dadas $k \ge 3$ coordenadas $(x_j, y_j)$:
   $$P(0) = \sum_{j=0}^{k-1} y_j \cdot \ell_j(0) \pmod p, \quad \text{con} \quad \ell_j(0) = \prod_{m \neq j} \frac{-x_m}{x_j - x_m} \pmod p$$

---

## 🚀 Despliegue Rápido

El proyecto incluye un script de Bash unificado ([`build_qorikey.sh`](file:///c:/Users/megac/Desktop/Proyectos/bc/QoriKey/build_qorikey.sh)) que genera los archivos necesarios, compila la imagen Docker, levanta el contenedor en segundo plano y ejecuta la suite de pruebas criptográficas automatizadas.

```bash
chmod +x build_qorikey.sh
./build_qorikey.sh
```

---

## 📡 Especificación de la API (REST)

El contenedor expone el servicio en el puerto `8082`:

### 1. `GET /api/ceremony`
Inicia la ceremonia criptográfica. Genera una nueva llave privada y devuelve los 5 fragmentos institucionales.
- **Respuesta:**
  ```json
  {
    "status": "ceremony_completed",
    "threshold": 3,
    "total_shares": 5,
    "simulated_paillier_key": "996839...",
    "shares": [
      {"x": 1, "y": "328033...", "institution": "ONPE..."},
      {"x": 2, "y": "356141...", "institution": "JNE..."},
      {"x": 3, "y": "843240...", "institution": "USS..."},
      {"x": 4, "y": "274428...", "institution": "Veedor..."},
      {"x": 5, "y": "187261...", "institution": "RENIEC..."}
    ]
  }
  ```

### 2. `POST /api/decrypt_tally`
Recibe el ciphertext del escrutinio acumulado de votos y un conjunto de fragmentos de llaves.
- **Cuerpo de la Petición:**
  ```json
  {
    "ciphertext": "0x9d72e4b8a1c3f6e5...",
    "shares": [
      {"x": 1, "y": "328033..."},
      {"x": 2, "y": "356141..."},
      {"x": 3, "y": "843240..."}
    ]
  }
  ```
- **Respuesta Exitosa ($k \ge 3$ llaves) - HTTP 200:**
  ```json
  {
    "status": "decrypted",
    "reconstructed_key": "996839...",
    "final_tally": 125000
  }
  ```
- **Respuesta de Rechazo ($k < 3$ llaves) - HTTP 403:**
  ```json
  {
    "detail": "HTTP 403 Forbidden: Umbral insuficiente. Se requieren al menos 3 llaves..."
  }
  ```

### 3. `GET /health`
Comprobación de salud y estado del microservicio.

---

## 🛠️ Tecnologías Empleadas
- **Python 3.10**
- **FastAPI** & **Uvicorn**
- **Pydantic v2**
- **Docker**
