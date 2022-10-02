from rest_framework import permissions
from .models import *
from rest_framework.permissions import BasePermission

# class IsBookOwner(permissions.BasePermission):
#     """
#     Check if user is Book owner or not.
#     """
#     def has_object_permission(self, request, view, obj):
#         return obj.owner == request.user

class IsadminUser(BasePermission):

    def has_permission(self, request, view):
        role_id = request.user.id
        print(role_id)
        try:
            User.objects.get()
            pass
        except Exception as e:
            pass
        if role_id == 1:
            return True
        return False
class IsSuperadminUser(BasePermission):

    def has_permission(self, request, view):
        role_id = request.user
        if role_id == 1:
            return True
        return False

# class IsadminUser(BasePermission):

#     def has_permission(self, request, view):
#         role_id = request.user.role_id
#         if role_id == 2:
#             return True
#         return False

class IsTechnicianUser(BasePermission):

    def has_permission(self, request, view):
        role_id = request.user
        print(role_id)
        if role_id == 3:
            return True
        return False

class IsOperatorUser(BasePermission):

    def has_permission(self, request, view):
        role_id = request.user
        if role_id == 4:
            return True
        return False
