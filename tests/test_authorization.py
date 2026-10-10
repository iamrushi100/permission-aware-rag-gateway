"""Unit tests for the pure version-one authorization decision."""

import unittest

from authorization import AccessType, Clearance, Document, User, UserRole, is_authorized


def make_user(
    *,
    identity="user-1",
    is_authenticated=True,
    is_active=True,
    clearance=Clearance.MEDIUM,
    role=UserRole.USER,
    department="engineering",
):
    """Build a valid user by default; tests override one field at a time."""

    return User(
        identity=identity,
        is_authenticated=is_authenticated,
        is_active=is_active,
        clearance=clearance,
        role=role,
        department=department,
    )


def make_document(
    *,
    sensitivity=Clearance.MEDIUM,
    access_type=AccessType.PUBLIC,
    department=None,
):
    """Build a valid public document by default."""

    return Document(
        sensitivity=sensitivity,
        access_type=access_type,
        department=department,
    )


class AuthorizationTests(unittest.TestCase):
    def test_medium_user_can_read_public_medium_document(self):
        user = make_user(clearance=Clearance.MEDIUM)
        document = make_document(
            sensitivity=Clearance.MEDIUM,
            access_type=AccessType.PUBLIC,
        )

        self.assertTrue(is_authorized(user, document))

    def test_low_user_cannot_read_public_medium_document(self):
        user = make_user(clearance=Clearance.LOW)
        document = make_document(sensitivity=Clearance.MEDIUM)

        self.assertFalse(is_authorized(user, document))

    def test_matching_department_user_can_read_restricted_document(self):
        user = make_user(clearance=Clearance.MEDIUM, department="engineering")
        document = make_document(
            sensitivity=Clearance.MEDIUM,
            access_type=AccessType.DEPARTMENT_RESTRICTED,
            department="engineering",
        )

        self.assertTrue(is_authorized(user, document))

    def test_user_cannot_read_another_departments_document(self):
        user = make_user(clearance=Clearance.MEDIUM, department="engineering")
        document = make_document(
            sensitivity=Clearance.MEDIUM,
            access_type=AccessType.DEPARTMENT_RESTRICTED,
            department="finance",
        )

        self.assertFalse(is_authorized(user, document))

    def test_administrator_does_not_bypass_clearance(self):
        user = make_user(
            clearance=Clearance.LOW,
            role=UserRole.ADMINISTRATOR,
        )
        document = make_document(sensitivity=Clearance.MEDIUM)

        self.assertFalse(is_authorized(user, document))

    def test_administrator_with_sufficient_clearance_can_read_public_document(self):
        user = make_user(
            identity="admin-1",
            is_authenticated=True,
            is_active=True,
            clearance=Clearance.MEDIUM,
            role=UserRole.ADMINISTRATOR,
        )
        document = make_document(
            sensitivity=Clearance.MEDIUM,
            access_type=AccessType.PUBLIC,
        )

        self.assertTrue(is_authorized(user, document))

    def test_equal_clearance_and_sensitivity_allow_access(self):
        user = make_user(clearance=Clearance.MEDIUM)
        document = make_document(sensitivity=Clearance.MEDIUM)

        self.assertTrue(is_authorized(user, document))

    def test_missing_or_blank_identity_is_denied(self):
        document = make_document()

        for identity in (None, "", "   "):
            with self.subTest(identity=identity):
                self.assertFalse(is_authorized(make_user(identity=identity), document))

    def test_unauthenticated_or_inactive_user_is_denied(self):
        document = make_document()

        self.assertFalse(
            is_authorized(make_user(is_authenticated=False), document)
        )
        self.assertFalse(is_authorized(make_user(is_active=False), document))

    def test_invalid_user_clearance_is_denied(self):
        user = make_user(clearance="medium")
        document = make_document()

        self.assertFalse(is_authorized(user, document))

    def test_missing_or_invalid_document_sensitivity_is_denied(self):
        user = make_user()

        for sensitivity in (None, "medium"):
            with self.subTest(sensitivity=sensitivity):
                document = make_document(sensitivity=sensitivity)
                self.assertFalse(is_authorized(user, document))

    def test_invalid_access_type_is_denied(self):
        user = make_user()
        document = make_document(access_type="public")

        self.assertFalse(is_authorized(user, document))

    def test_missing_or_blank_department_is_denied_for_restricted_document(self):
        document = make_document(
            access_type=AccessType.DEPARTMENT_RESTRICTED,
            department="engineering",
        )

        for department in (None, "", "   "):
            with self.subTest(user_department=department):
                user = make_user(department=department)
                self.assertFalse(is_authorized(user, document))

        user = make_user(department="engineering")
        for department in (None, "", "   "):
            with self.subTest(document_department=department):
                invalid_document = make_document(
                    access_type=AccessType.DEPARTMENT_RESTRICTED,
                    department=department,
                )
                self.assertFalse(is_authorized(user, invalid_document))

    def test_department_match_is_case_sensitive(self):
        user = make_user(department="Engineering")
        document = make_document(
            access_type=AccessType.DEPARTMENT_RESTRICTED,
            department="engineering",
        )

        self.assertFalse(is_authorized(user, document))

    def test_invalid_role_and_malformed_record_inputs_are_denied(self):
        user = make_user(role="administrator")
        document = make_document()

        self.assertFalse(is_authorized(user, document))
        self.assertFalse(is_authorized(None, document))
        self.assertFalse(is_authorized(make_user(), object()))


if __name__ == "__main__":
    unittest.main()
