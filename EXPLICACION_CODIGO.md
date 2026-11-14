# Documentación Técnica y Explicación del Código - QoriKey

Este documento detalla la arquitectura técnica, las decisiones de diseño criptográfico y el funcionamiento paso a paso del código fuente de **QoriKey**.

---

## 1. Visión General del Sistema

En un sistema de votación electrónica respaldado por blockchain, los votos de los ciudadanos se cifran individualmente mediante esquemas de **Criptografía Homomórfica** (como Paillier). Esto permite que los nodos sumen los votos directamente en su forma cifrada sin revelar la preferencia de ningún elector:

$$\text{Ciphertext}_{\text{total}} = \prod_{i=1}^{V} c_i \pmod{n^2}$$

El riesgo crítico radica en **quién custodia la llave privada** necesaria para descifrar el escrutinio final. Si una sola entidad retiene la llave completa:
1. Existe un **Punto Único de Fallo (SPOF)**: si la llave se pierde, los resultados son irrecuperables.
2. Existe un **Riesgo de Coerción o Fraude**: si la entidad es vulnerada o coaccionada, puede manipular o filtrar el resultado antes de tiempo.

**QoriKey** elimina este problema utilizando el **Esquema de Secreto Compartido de Shamir (SSS)**, garantizando que ninguna entidad individual conozca la llave privada, y requiriendo un consenso multipartito estricto ($k=3$ de $n=5$) para el escrutinio final.

---

## 2. Desglose del Código: `main.py`

### 2.1. Selección del Campo Finito Primo ($\mathbb{F}_p$)
```python
PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)
```
- **¿Por qué un primo de 2048 bits?** El algoritmo de Shamir debe ejecutarse sobre un campo primo $\mathbb{F}_p$ estrictamente mayor que el secreto compartido ($p > S$). Dado que las llaves privadas de Paillier o RSA en producción son de 2048 bits, utilizar el primo estándar del **RFC 3526** asegura compatibilidad directa sin desbordamientos de campo ni pérdidas de entropía.
- **Seguridad Teórica:** En un campo primo $\mathbb{F}_p$, la probabilidad de adivinar el secreto con menos de $k$ fragmentos es exactamente $\frac{1}{p}$, lo que proporciona **seguridad teórica de la información** (Information-Theoretic Security).

---

### 2.2. Ceremonia Criptográfica (`GET /api/ceremony`)

```python
paillier_private_key = secrets.randbits(256)

a0 = paillier_private_key
a1 = secrets.randbelow(PRIME - 1) + 1
a2 = secrets.randbelow(PRIME - 1) + 1
```
- Se utiliza el módulo `secrets` de Python (que accede a `/dev/urandom` o al subsistema CSPRNG del sistema operativo) para prevenir sesgos de números pseudoaleatorios.
- Se construye un polinomio de grado $k - 1 = 2$:
  $$P(x) = a_0 + a_1 x + a_2 x^2 \pmod p$$
  donde $a_0 = S$ (la llave secreta).
- Luego se itera sobre los 5 custodios ($x \in \{1, 2, 3, 4, 5\}$):
  ```python
  y_val = (a0 + (a1 * x_val) + (a2 * (x_val ** 2))) % PRIME
  ```
  Cada custodio recibe un par ordenado $(x, y)$ donde $y$ es un entero gigante de 2048 bits.

---

### 2.3. Desencriptación y Reconstrucción (`POST /api/decrypt_tally`)

#### A. Validación de Seguridad y Filtrado de Coordenadas:
```python
if len(received_shares) < THRESHOLD:
    raise HTTPException(
        status_code=403,
        detail=f"HTTP 403 Forbidden: Umbral insuficiente..."
    )

unique_shares = {}
for item in received_shares:
    if item.x not in unique_shares:
        unique_shares[item.x] = int(item.y)

if len(unique_shares) < THRESHOLD:
    raise HTTPException(status_code=403, detail="Fragmentos duplicados detectados...")
```
- Verifica rigurosamente que se alcancen al menos $k=3$ fragmentos. Si se envían 1 o 2 llaves, o si un atacante envía la misma llave duplicada para inflar la cuenta, el servicio responde con **HTTP 403 Forbidden**.

#### B. Interpolación de Lagrange en $x = 0$:
Para reconstruir el término independiente $P(0) = a_0$, se aplica la fórmula de Lagrange evaluada en $0$:

```python
reconstructed_key = 0

for j, (xj, yj) in enumerate(points):
    numerator = 1
    denominator = 1
    for m, (xm, _) in enumerate(points):
        if m == j:
            continue
        numerator = (numerator * (-xm)) % PRIME
        denominator = (denominator * (xj - xm)) % PRIME

    # Inverso multiplicativo modular (Euclides Extendido)
    inv_denominator = pow(denominator, -1, PRIME)
    lagrange_basis = (numerator * inv_denominator) % PRIME
    term = (yj * lagrange_basis) % PRIME
    reconstructed_key = (reconstructed_key + term) % PRIME
```

- **Inverso Modular:** En aritmética de campos finitos, la división $\frac{a}{b}$ se realiza como la multiplicación por el inverso multiplicativo: $a \cdot b^{-1} \pmod p$.
- En Python 3.8+, `pow(b, -1, p)` computa de forma nativa y ultra-eficiente el inverso modular usando el **Algoritmo Extendido de Euclides**, garantizando que el cálculo se ejecute en microsegundos aun con números de 2048 bits.

---

## 3. Desglose de Contenedorización: `Dockerfile`

```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8082
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8082"]
```
- **Base `python:3.10-slim`**: Reduce la superficie de ataque y el peso de la imagen (< 150 MB).
- **Capa de dependencias con `--no-cache-dir`**: Optimiza el almacenamiento descartando archivos temporales de `pip`.
- **Servidor ASGI Uvicorn**: Expuesto en el puerto `8082` escuchando en todas las interfaces de red (`0.0.0.0`).

---

## 4. Desglose de Orquestación y Pruebas: `build_qorikey.sh`

El script implementa una tubería de despliegue y validación continua:
1. **Generación In-Situ**: Crea `requirements.txt`, `main.py` y `Dockerfile` usando sintaxis hermética `cat << 'EOF'`.
2. **Build & Run**: Compila la imagen con `docker build -t qorikey-image .` y levanta el contenedor con `-d -p 8082:8082 --name qorikey-app`.
3. **Health Check Polling**: Espera de 3 segundos y bucle de reintento contra `/health`.
4. **Prueba de Ceremonia**: Ejecuta `curl` contra `/api/ceremony`, guarda la salida y formatea la distribución de llaves institucionales en consola.
5. **Prueba de Fracaso (2 llaves)**: Construye un payload con solo 2 instituciones (ONPE y USS). Verifica que el código HTTP sea **403 Forbidden**.
6. **Prueba de Éxito (3 llaves)**: Construye un payload con 3 instituciones (ONPE, JNE y USS). Verifica código **200 OK**, comprueba que la llave reconstruida coincide bit a bit con la original de la ceremonia, y certifica la revelación del escrutinio final de **125,000 votos**.
