from rest_framework.permissions import BasePermission
from authapi import models
class IsAdmin(BasePermission):
   def has_permission(self, request, view):
       if hasattr(request.user,'role_id'):
            try:
                usr_rle = models.UserRole.objects.get(pk=request.user.role_id)
            except Exception as e:
                return False
            if usr_rle.role_name == 'Admin':
               return True #request.user.role_id == 4
       return False

class IsSuperAdmin(BasePermission):
   def has_permission(self, request, view):
       if hasattr(request.user,'role_id'):
           usr_rle = models.user_role.objects.get(pk=request.user.role_id)
           if usr_rle.role_name == 'SuperAdmin':
               return True #request.user.role_id == 4
       return False
   
class IsOperator(BasePermission):
       def has_permission(self, request, view):
        if hasattr(request.user,'role_id'):
            usr_rle = models.user_role.objects.get(pk=request.user.role_id)
            if usr_rle.role_name == 'Operators':
                return True #request.user.role_id == 4
        return False

class IsTechnician(BasePermission):
       def has_permission(self, request, view):
        if hasattr(request.user,'role_id'):
            usr_rle = models.user_role.objects.get(pk=request.user.role_id)
            if usr_rle.role_name == 'Technician':
                return True #request.user.role_id == 4
        return False