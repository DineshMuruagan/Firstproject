# Generated by Django 3.2.15 on 2022-10-02 10:43

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authapi', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='userrights',
            old_name='rights',
            new_name='rights_name',
        ),
        migrations.RenameField(
            model_name='userrole',
            old_name='role',
            new_name='role_name',
        ),
    ]