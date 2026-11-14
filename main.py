import secrets
from typing import List, Optional, Union
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="QoriKey Cryptographic Custody & Distributed Decryption",
    description="Microservicio de custodia de llaves criptográficas basado en Shamir's Secret Sharing (k=3, n=5).",
    version="1.0.0"
)

# ==============================================================================
# CAMPO FINITO PRIMO F_p (RFC 3526 2048-bit MODP Prime)
# p = 2^2048 - 2^1984 - 1 + 2^64 * {[2^1918 pi] + 124476}
# Proporciona seguridad criptográfica estándar y capacidad para enteros gigantes de Paillier
# ==============================================================================
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

TOTAL_SHARES = 5
THRESHOLD = 3

INSTITUTIONS = [
    {"index": 1, "institution": "ONPE (Oficina Nacional de Procesos Electorales)"},
    {"index": 2, "institution": "JNE (Jurado Nacional de Elecciones)"},
    {"index": 3, "institution": "USS (Universidad Señor de Sipán)"},
    {"index": 4, "institution": "Veedor (Veeduría Internacional / Sociedad Civil)"},
    {"index": 5, "institution": "RENIEC (Registro Nacional de Identificación y Estado Civil)"}
]

# Modelos Pydantic
class ShareItem(BaseModel):
    x: int = Field(..., description="Coordenada x (identificador del custodio)")
    y: Union[str, int] = Field(..., description="Evaluación polinómica P(x) mod p")
    institution: Optional[str] = Field(None, description="Nombre de la entidad custodia")

class CeremonyResponse(BaseModel):
    status: str
    threshold: int
    total_shares: int
    simulated_paillier_key: str
    shares: List[ShareItem]

class DecryptTallyRequest(BaseModel):
    ciphertext: str = Field(..., description="Total de votos homomórficos cifrados proveniente de QoriCore")
    shares: List[ShareItem] = Field(..., description="Lista de fragmentos presentados por los custodios")

class DecryptTallyResponse(BaseModel):
    status: str
    reconstructed_key: str
    final_tally: int

# ==============================================================================
# ENDPOINT 1: GET /api/ceremony
# ==============================================================================
@app.get("/api/ceremony", response_model=CeremonyResponse)
def ceremony():
    """
    Ceremonia Criptográfica de Generación y Distribución de Secreto:
    1. Genera una llave privada simulada de Paillier (un entero gigante criptográfico).
    2. Construye un polinomio aleatorio de grado (threshold - 1) = 2 sobre F_p:
       P(x) = (a_0 + a_1*x + a_2*x^2) mod p, con a_0 = private_key.
    3. Evalúa P(x) en x in {1, 2, 3, 4, 5} para las 5 entidades custodias.
    """
    # Llave privada simulada de Paillier: entero gigante aleatorio criptográficamente seguro
    paillier_private_key = secrets.randbits(256)

    # Coeficientes aleatorios en F_p
    a0 = paillier_private_key
    a1 = secrets.randbelow(PRIME - 1) + 1
    a2 = secrets.randbelow(PRIME - 1) + 1

    generated_shares = []
    for inst in INSTITUTIONS:
        x_val = inst["index"]
        # P(x) mod p
        y_val = (a0 + (a1 * x_val) + (a2 * (x_val ** 2))) % PRIME
        generated_shares.append(ShareItem(
            x=x_val,
            y=str(y_val),
            institution=inst["institution"]
        ))

    return CeremonyResponse(
        status="ceremony_completed",
        threshold=THRESHOLD,
        total_shares=TOTAL_SHARES,
        simulated_paillier_key=str(paillier_private_key),
        shares=generated_shares
    )

# ==============================================================================
# ENDPOINT 2: POST /api/decrypt_tally
# ==============================================================================
@app.post("/api/decrypt_tally", response_model=DecryptTallyResponse)
def decrypt_tally(payload: DecryptTallyRequest):
    """
    Reconstrucción de Secreto por Interpolación de Lagrange y Desencriptación:
    1. Verifica que existan al menos 3 fragmentos válidos. Si no, devuelve HTTP 403 Forbidden.
    2. Usa Interpolación Polinomial de Lagrange en x=0 para hallar P(0) = a_0 mod p.
    3. Simula la desencriptación homomórfica de Paillier con la llave exacta reconstruida.
    """
    received_shares = payload.shares

    # Validación de umbral mínimo de llaves
    if len(received_shares) < THRESHOLD:
        raise HTTPException(
            status_code=403,
            detail=f"HTTP 403 Forbidden: Umbral insuficiente. Se requieren al menos {THRESHOLD} llaves para reconstruir el secreto (recibidas: {len(received_shares)})."
        )

    # Filtrar llaves por coordenada x única
    unique_shares = {}
    for item in received_shares:
        if item.x not in unique_shares:
            unique_shares[item.x] = int(item.y)

    if len(unique_shares) < THRESHOLD:
        raise HTTPException(
            status_code=403,
            detail=f"HTTP 403 Forbidden: Se detectaron fragmentos duplicados. Se requieren al menos {THRESHOLD} custodios distintos."
        )

    # Tomar exactamente THRESHOLD puntos para la reconstrucción exacta
    points = list(unique_shares.items())[:THRESHOLD]

    # Interpolación de Lagrange en x = 0 sobre F_p:
    # P(0) = \sum_{j=0}^{k-1} y_j * l_j(0) mod p
    # l_j(0) = \prod_{m \neq j} \frac{-x_m}{x_j - x_m} mod p
    reconstructed_key = 0

    for j, (xj, yj) in enumerate(points):
        numerator = 1
        denominator = 1
        for m, (xm, _) in enumerate(points):
            if m == j:
                continue
            numerator = (numerator * (-xm)) % PRIME
            denominator = (denominator * (xj - xm)) % PRIME

        # Inverso multiplicativo modular (Euclides Extendido / Fermat)
        inv_denominator = pow(denominator, -1, PRIME)
        lagrange_basis = (numerator * inv_denominator) % PRIME
        term = (yj * lagrange_basis) % PRIME
        reconstructed_key = (reconstructed_key + term) % PRIME

    # Simulación de desencriptación homomórfica de Paillier
    return DecryptTallyResponse(
        status="decrypted",
        reconstructed_key=str(reconstructed_key),
        final_tally=125000
    )

@app.get("/health")
def health():
    return {"status": "ok", "app": "QoriKey"}
