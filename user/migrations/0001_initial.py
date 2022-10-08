# Generated by Django 4.1.2 on 2022-10-08 06:12

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import user.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('first_name', models.CharField(blank=True, max_length=256, null=True, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=256, null=True, verbose_name='last name')),
                ('email', models.EmailField(blank=True, max_length=254, null=True, verbose_name='email address')),
                ('mobile', models.CharField(blank=True, db_index=True, max_length=16, null=True, verbose_name='mobiles')),
                ('username', models.CharField(blank=True, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, null=True, unique=True, verbose_name='username')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('status', models.CharField(choices=[('active', 'active'), ('inactive', 'inactive'), ('deleted', 'deleted')], default='active', max_length=20)),
                ('role', models.CharField(choices=[('superuser', 'superuser'), ('account_admin', 'account_admin'), ('user', 'user')], default='staff', max_length=20)),
                ('two_step_verification', models.BooleanField(default=False)),
                ('login_otp', models.CharField(blank=True, max_length=10, null=True)),
                ('login_otp_time', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'db_table': 'user',
            },
            managers=[
                ('objects', user.models.CustomUserManager()),
            ],
        ),
    ]
