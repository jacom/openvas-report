import logging

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from django.db import connections

from passlib.hash import sha512_crypt

logger = logging.getLogger(__name__)


class GVMBackend(BaseBackend):
    """Authenticate against the GVM (gvmd) database users table."""

    def authenticate(self, request, username=None, password=None):
        if username is None or password is None:
            return None

        stored_hash = self._get_gvm_hash(username)
        if stored_hash is None:
            return None

        try:
            if not sha512_crypt.verify(password, stored_hash):
                return None
        except Exception:
            logger.exception("Error verifying password for user %s", username)
            return None

        user, _ = User.objects.get_or_create(
            username=username,
            defaults={'is_active': True},
        )
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    @staticmethod
    def _get_gvm_hash(username):
        """Fetch the password hash from the gvmd users table."""
        try:
            with connections['gvmd'].cursor() as cursor:
                cursor.execute(
                    "SELECT password FROM users WHERE name = %s",
                    [username],
                )
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception:
            logger.exception("Error querying gvmd users table")
            return None
