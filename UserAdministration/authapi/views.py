from pickle import GET
from django.shortcuts import render
from drf_yasg.inspectors.view import SwaggerAutoSchema

from rest_framework.response import *
from rest_framework import generics
from rest_framework.generics import GenericAPIView
from drf_yasg import *
from knox.serializers import *
from rest_framework import decorators
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from authapi.serializers import *
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS


from knox.models import AuthToken
# from rest_framework_swagger.views import get_swagger_view
from rest_framework import permissions
from rest_framework.permissions import BasePermission
# from rest_framework.permissions import IsAuthenticated
from .permissions import *
# from UserAdministration.authapi.serializers import UserRoleSerializer



# Create your views here.
# from rest_framework import permissions

# class IsadminUser(BasePermission):

#     def has_permission(self, request, view):
#         role_id = request.user.role_id
#         if role_id == 1:
#             return True
#         return False
# class IsSuperadminUser(BasePermission):

#     def has_permission(self, request, view):
#         role_id = request.user.role_id
#         if role_id == 1:
#             return True
#         return False

# # class IsadminUser(BasePermission):

# #     def has_permission(self, request, view):
# #         role_id = request.user.role_id
# #         if role_id == 2:
# #             return True
# #         return False

# class IsTechnicianUser(BasePermission):

#     def has_permission(self, request, view):
#         role_id = request.user.role_id
#         if role_id == 3:
#             return True
#         return False

# class IsOperatorUser(BasePermission):

#     def has_permission(self, request, view):
#         role_id = request.user.role_id
#         if role_id == 4:
#             return True
#         return False


from knox.auth import TokenAuthentication
from rest_framework.authentication import BasicAuthentication


class CreateRole(generics.GenericAPIView):
    # permission_classes = [IsadminUser]
    # authentication_classes = [BasicAuthentication]
  
    # authentication_classes = (TokenAuthentication,)
    @swagger_auto_schema(request_body=UserRoleSerializer,tags=['auth'])    

    def post(self,request):
        print(request.user,"dfdff")
        try:
            
            serializer =UserRoleSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                print(serializer.data)
                return Response({"Message":"created_successfully",})
            return Response({"Message":"Invalid Request"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Message":str(e)},status=status.HTTP_400_BAD_REQUEST)


class EditRole(generics.GenericAPIView):
    # permission_classes = [IsadminUser|IsSuperadminUser]    
    # permission_classes = [IsAuthenticated]
    @swagger_auto_schema(request_body=EditUserRoleSerializer,tags=['auth'])
    def post(self,request):
        try:
            edit_role_info = UserRole.objects.get(pk=request.data['id'])
        except Exception as e:
            return Response({"msg":"Invalid Request id"},status=status.HTTP_400_BAD_REQUEST)
        print("edit_role_info",edit_role_info)
        try:
            serializer = EditUserRoleSerializer(edit_role_info,request.data)
            # print(serializer.data)
            print(serializer,"dfdfd")
        # if serializer.is_valid():
            serializer.is_valid(raise_exception=True)
            userrole_info = serializer.save()
            print(userrole_info)
            print("is_valid")
            edit1_info = {
            "id":userrole_info.id,
            'role_name':userrole_info.role_name,
            "desc":userrole_info.desc,
            'status':userrole_info.status,
            'order_id':userrole_info.order_id,
            'msg':"Edited Successfully"
            }
            return Response(edit1_info,status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"msg",str(e)}, status=status.HTTP_400_BAD_REQUEST)




@swagger_auto_schema(method='get',tags=['auth'])
@api_view(["GET"])
# @permission_classes([IsadminUser|IsSuperadminUser])

def RoleList(request):
    print(request.user)
    print(request.user.id)
    print(request.user.role_id)
    usr_role_info = UserRole.objects.all().values()
    return Response(usr_role_info)



class CreateRights(generics.GenericAPIView):
    #permission_classes = [IsadminUser|IsSuperadminUser]    
    @swagger_auto_schema(request_body=UserRightSerializer,tags=['auth'])
    def post(self,request):
        try:
            serializer =UserRightSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                print(serializer.data)
                return Response({"Message":"created_successfully",'data':serializer.data})
            return Response({"Message":"Invalid Request"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Message":str(e)},status=status.HTTP_400_BAD_REQUEST)

class EditRights(generics.GenericAPIView):
    #permission_classes = [IsadminUser|IsSuperadminUser]    
    @swagger_auto_schema(request_body=EditUserRightsSerializer,tags=['auth'])
    def post(self,request):
        try:
            edit_rights_info = UserRights.objects.get(pk=request.data['id'])
        except Exception as e:
            return Response({"msg":"Invalid Request id"},status=status.HTTP_400_BAD_REQUEST)
        try:
            serializer = EditUserRightsSerializer(edit_rights_info,request.data)
            serializer.is_valid(raise_exception=True)
            userrole_info = serializer.save()
            print(serializer.data,"dfdfdfd1")
            edit_info = {
            "id":userrole_info.id,
            'role_name':userrole_info.rights_name,
            "desc":userrole_info.desc,
            'status':userrole_info.status,
            'order_id':userrole_info.order_id,
            'msg':"Edited Successfully"
            }
            return Response(edit_info,status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"msg",str(e)}, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method='get',tags=['auth'])
@api_view(["GET"])
# ['GET', 'POST']
#@permission_classes([IsadminUser|IsSuperadminUser])

def RightsList(request):
    usr_rights_info = UserRights.objects.all().values()
    return Response(usr_rights_info)


class CreateUser(generics.GenericAPIView):
    #permission_classes = [IsadminUser|IsSuperadminUser]   
    @swagger_auto_schema(request_body=UserSerializer,tags=['auth'])
    def post(self,request):
        try:
            serializer =UserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                print(serializer.data)
                return Response({"Message":"User created_successfully",'data':serializer.data})
            return Response({"Message":"Invalid Request"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Message":str(e)},status=status.HTTP_400_BAD_REQUEST)


class EditUser(generics.GenericAPIView):   
    @swagger_auto_schema(request_body=EditUserSerializer,tags=['auth'])
    def post(self,request):
        try:
            usr_info = User.objects.get(id=request.data['id'])
        except Exception as e:
            return Response({"Message":"Invalid User"})
        try:
            serializer =EditUserSerializer(usr_info,data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                print(serializer.data)
                return Response({"Message":"User Edited_successfully",'data':serializer.data})
            return Response({"Message11":"Invalid Request"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"Message111":str(e)},status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(method='get',tags=['auth'])
@api_view(["GET"])
#@permission_classes([IsadminUser|IsSuperadminUser])

def UserList(request):
    print(request.user)
    usr_rights_info = User.objects.all().values()
    return Response(usr_rights_info)

class LoginView(generics.GenericAPIView):
    # permission_classes =  [IsAuthenticated] 

    @swagger_auto_schema(request_body=AuthSerializer,tags=['auth'])
    # def post(self,request):
        # serializer = AuthSerializer(data=request.data)
        # serializer.is_valid(raise_exception=True)
        # user = serializer.data
        # print(user)
        # return Response({
        #     "user": UserSerializer(user).data,
        #     "token": AuthToken.objects.create(user)[1]
        # })
    # serializer_class = LoginUserSerializer

    def post(self, request, *args, **kwargs):
        # serializer = self.get_serializer(data=request.data)
        serrializer = LoginUserSerializer(data=request.data)
        serrializer.is_valid(raise_exception=True)
        user = serrializer.validated_data
        return Response({
            "user": UserSerializer(user, context=self.get_serializer_context()).data,
            "token": AuthToken.objects.create(user)[1]
        })


class DeleteUser(generics.GenericAPIView):
    @swagger_auto_schema(request_body=UserIdSerializer,tags=['auth'])
    def post(self,request):
        try:
            usr_info = User.objects.get(id=request.data['usr_id'])
            usr_info.delete()
            return Response({"msg":"Deleted Successfully."})
        except Exception as e:
            return Response({"msg":"User is not exist"},status=status.HTTP_400_BAD_REQUEST)

class DeleteRole(generics.GenericAPIView):
    @swagger_auto_schema(request_body=UserRoleIdSerializer,tags=['auth'])
    def post(self,request):
        try:
            usr_info = UserRole.objects.get(id=request.data['role_id'])
            usr_info.delete()
            return Response({"msg":"Deleted Successfully."})
        except Exception as e:
            return Response({"msg":"User_role is not exist"},status=status.HTTP_400_BAD_REQUEST)

class DeleteRights(generics.GenericAPIView):
    @swagger_auto_schema(request_body=UserRightsIdSerializer,tags=['auth'])
    def post(self,request):
        try:
            usr_info = UserRightSerializer.objects.get(id=request.data['role_id'])
            usr_info.delete()
            return Response({"msg":"Deleted Successfully."})
        except Exception as e:
            return Response({"msg":"user_rights is not exist"},status=status.HTTP_400_BAD_REQUEST)