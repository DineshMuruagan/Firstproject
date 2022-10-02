from email.policy import default
from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.

class UserRole(models.Model):
    role_name = models.CharField(max_length=100,null=True,blank=True)
    desc = models.CharField(max_length=100,null=True,blank=True)
    status = models.BooleanField(default=True,null=True,blank=True)
    order_id = models.IntegerField(null=True,blank=True)

class UserRights(models.Model):
    rights_name = models.CharField(max_length=30,null=True,blank=True)
    desc = models.CharField(max_length=100,null=True,blank=True)
    status = models.BooleanField(default=True,null=True,blank=True)
    order_id = models.IntegerField(null=True,blank=True)

class User(AbstractUser):
    role  = models.ForeignKey(UserRole,related_name='rn1_user_role',on_delete=models.CASCADE,null=True,blank=True)
    status = models.BooleanField(default=True,null=True,blank=True)
    gender = models.CharField(max_length=3,null=True,blank=True)


class RoleRightsMapper(models.Model):
    role = models.ForeignKey(UserRole,related_name='rn2_user_role',on_delete=models.CASCADE,null=True,blank=True)
    rights = models.ForeignKey(UserRights,related_name='rn1_user_rights',on_delete=models.CASCADE,null=True,blank=True)
    


