"""Version Catalog management API (manually-managed reference data) + version
intelligence evaluation. Read-only with respect to firewalls."""
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.version_catalog import VersionCatalogEntry
from app.security.identity import get_current_user, require_capability
from app.security.rbac import CAP_MANAGE_SETTINGS

router = APIRouter(prefix="/api/version-catalog", tags=["version-catalog"])


class CatalogIn(BaseModel):
    vendor: str
    product: Optional[str] = None
    model_family: Optional[str] = None
    os_name: Optional[str] = None
    release_train: Optional[str] = None
    latest_known_version: Optional[str] = None
    recommended_version: Optional[str] = None
    minimum_supported_version: Optional[str] = None
    eol_versions: Optional[List[str]] = None
    release_date: Optional[str] = None
    support_status: Optional[str] = None
    advisory_url: Optional[str] = None
    notes: Optional[str] = None


def _dict(e: VersionCatalogEntry) -> dict:
    return {
        "id": e.id, "vendor": e.vendor, "product": e.product, "model_family": e.model_family,
        "os_name": e.os_name, "release_train": e.release_train,
        "latest_known_version": e.latest_known_version, "recommended_version": e.recommended_version,
        "minimum_supported_version": e.minimum_supported_version, "eol_versions": e.eol_versions or [],
        "release_date": e.release_date, "support_status": e.support_status,
        "advisory_url": e.advisory_url, "notes": e.notes,
        "last_updated": e.last_updated.isoformat() if e.last_updated else None,
    }


@router.get("")
def list_catalog(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.query(VersionCatalogEntry).order_by(VersionCatalogEntry.vendor, VersionCatalogEntry.release_train).all()
    return {"entries": [_dict(e) for e in rows]}


@router.post("")
def create_entry(body: CatalogIn, db: Session = Depends(get_db),
                 user: User = Depends(require_capability(CAP_MANAGE_SETTINGS))):
    e = VersionCatalogEntry(**body.model_dump())
    db.add(e); db.commit(); db.refresh(e)
    return _dict(e)


@router.put("/{entry_id}")
def update_entry(entry_id: str, body: CatalogIn, db: Session = Depends(get_db),
                 user: User = Depends(require_capability(CAP_MANAGE_SETTINGS))):
    e = db.query(VersionCatalogEntry).filter(VersionCatalogEntry.id == entry_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="Catalog entry not found.")
    for k, v in body.model_dump().items():
        setattr(e, k, v)
    db.commit(); db.refresh(e)
    return _dict(e)


@router.delete("/{entry_id}")
def delete_entry(entry_id: str, db: Session = Depends(get_db),
                 user: User = Depends(require_capability(CAP_MANAGE_SETTINGS))):
    e = db.query(VersionCatalogEntry).filter(VersionCatalogEntry.id == entry_id).first()
    if not e:
        raise HTTPException(status_code=404, detail="Catalog entry not found.")
    db.delete(e); db.commit()
    return {"deleted": entry_id}


@router.post("/import")
def import_catalog(entries: List[CatalogIn], replace: bool = False, db: Session = Depends(get_db),
                   user: User = Depends(require_capability(CAP_MANAGE_SETTINGS))):
    """Bulk import catalog entries (JSON). replace=true clears the catalog first."""
    if replace:
        db.query(VersionCatalogEntry).delete()
    created = 0
    for item in entries:
        db.add(VersionCatalogEntry(**item.model_dump()))
        created += 1
    db.commit()
    return {"imported": created, "replaced": replace}
