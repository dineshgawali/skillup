from enum import unique
from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, UserManager, Group
from django.utils.translation import gettext_lazy as _


class CustomUserManager(UserManager):
    def _create_user(self, username, password, **extra_fields):
        """
        Create and save a user with the given email, and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(username, password, **extra_fields)

    def create_superuser(self, username, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('mobile', username)
        group, created = Group.objects.get_or_create(name='super_admin')
        extra_fields.setdefault('group_id', group.id)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(username, password, **extra_fields)

class UserPermissionMixin(PermissionsMixin):
    is_superuser = models.BooleanField(_('superuser status'),
                                       default=False,
                                       help_text=_(
                                           'Designates that this user has all permissions without '
                                           'explicitly assigning them.'
                                       ),
                                       )

    groups = None
    user_permissions = None
    is_staff = False

    class Meta:
        abstract = True

    def get_group_permissions(self, obj=None):
        pass

    def get_all_permissions(self, obj=None):
        pass


class User(AbstractBaseUser, UserPermissionMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.

    email and password are required. Other fields are optional.
    is_active : restrict from login true when login, false is not login
    is_superuser/ is_staff : for superuser, admin this is true
    is_verified : users in category dealership and showrooms are verified by admin
    """
    first_name = models.CharField(_('first name'), max_length=256, blank=True, null=True)
    last_name = models.CharField(_('last name'), max_length=256, blank=True, null=True)
    email = models.EmailField(_('email address'), null=True, blank=True)
    mobile = models.CharField(_('mobiles'), max_length=16, null=True, blank=True, db_index=True)
    username = models.CharField(
        _('username'),
        max_length=150,
        help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        null=True,
        blank=True,
        unique=True
    )
    # group = models.ForeignKey(Group, null=True, on_delete=models.CASCADE)
    is_staff = models.BooleanField(_('staff status'),
                                   default=False,
                                   help_text=_('Designates whether the user can log into this admin site.'),
                                   )
    is_active = models.BooleanField(_('active'), default=True,
                                    help_text=_('Designates whether this user should be treated as active. '
                                                'Unselect this instead of deleting accounts.'), )
    STATUS_CHOICES = (
        ('active', 'active'),
        ('inactive', 'inactive'),
        ('deleted', 'deleted')
    )
    status = models.CharField(choices=STATUS_CHOICES, max_length=20, default='active')
    GROUP_CHOICES = (
        ('superuser', 'superuser'),
        ('account_admin', 'account_admin'),
        ('user', 'user')
    )
    created_by = models.ForeignKey("self", on_delete=models.CASCADE, null=True, blank=True)
    role = models.CharField(choices=GROUP_CHOICES, max_length=20, default='staff')
    objects = CustomUserManager()
    two_step_verification = models.BooleanField(default=False)
    login_otp = models.CharField(max_length=10, blank=True, null=True)
    login_otp_time = models.DateTimeField(blank=True, null=True)

    # image = models.ForeignKey(Files, on_delete=models.SET_NULL, blank=True, null=True)
    # otp = models.CharField(max_length=20, blank=True, null=True)
    # otp_time = models.DateTimeField(blank=True, null=True)
    # new_otp = models.CharField(max_length=20, blank=True, null=True)
    # is_main_aa = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # dashboard = models.TextField(null=True)
    # selected_dashboard = models.TextField(null=True)
    # default_dashboard = models.TextField(null=True)
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'user'
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """
        Returns the short name for the user.
        """
        return self.first_name
