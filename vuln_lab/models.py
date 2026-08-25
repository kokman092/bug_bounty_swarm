"""
vuln_lab/models.py
──────────────────
SQLite data models for the intentionally vulnerable test lab.
IDs are sequential integers on purpose to enable IDOR / BOLA demonstrations.
"""
from dataclasses import dataclass


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    role: str
    token: str


@dataclass
class Order:
    id: int
    user_id: int
    item: str
    amount: float
    invoice_path: str


@dataclass
class Product:
    id: int
    name: str
    price: float
