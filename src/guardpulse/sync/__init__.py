"""Phase 6: Google sign-in + end-to-end encrypted sync between an account's phones.

- ``crypto``  - AES-256-GCM sealing of snapshots; the pairing code
- ``state``   - snapshot export + the fail-safe three-way merge
- ``firebase``- Firebase Auth + Firestore over plain HTTPS (free Spark plan)
- ``manager`` - ties it together for the app
"""
