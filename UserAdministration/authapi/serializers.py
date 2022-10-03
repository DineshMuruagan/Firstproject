
from wsgiref import validate
from django.contrib.auth.models import User
from django.contrib.auth import  authenticate

from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from authapi.models import *
# from UserAdministration.authapi.models import UserRole


class UserSerializer(serializers.ModelSerializer):
    '''serializer for the user object'''
    class Meta:
        model = User
        fields = ('username', 'password','role','gender')
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}
    
    def create(self, validated_data):
        print("crate_function called")
        usr = User.objects.create_user(**validated_data)
        try:
            print('role_info is checking')
            print("role_id",validated_data['role'].id)
            role_info = UserRole.objects.get(pk=1)
        except Exception as e:
            print("usr_role is not valid")
            raise serializers.ValidationError({"msg":"User Role is not valid..."})
        usr_role_rights = []
        print("usr_role_checking")
        if role_info.id == 1 or role_info.id == 2:
            print("admin and superadmin")
            usr_rights = UserRights.objects.all()
            for i in range(0,len(usr_rights)):
                usr_role_rights.append(RoleRightsMapper(role=validated_data['role'],rights_id = i+1))
            RoleRightsMapper.objects.bulk_create(usr_role_rights)
        elif role_info.role_name == 'Operators':
            print("operators")
            for i in range(1,4):
                usr_role_rights.append(RoleRightsMapper(role_id=validated_data['role'],rights_id = i+1))
            RoleRightsMapper.objects.bulk_create(usr_role_rights)
        else:
            print("noraml user")
            RoleRightsMapper.objects.create(role=validated_data['role'],rights_id=3)
        return usr

class EditUserSerializer(serializers.ModelSerializer):
    '''serializer for the user object'''
    id = serializers.IntegerField()
    class Meta:
        model = User
        fields = ('id','username','role','gender')
        # extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}
    
    def update(self, instance,validated_data):
        print("crate_function called")
        instance.username = validated_data['username']
        instance.role = validated_data['role']
        instance.gender = validated_data['gender']
        try:
            print('role_info is checking')
            print("role_id",validated_data['role'].id)
            role_info = UserRole.objects.get(pk=1)
        except Exception as e:
            print("usr_role is not valid")
            raise serializers.ValidationError({"msg":"User Role is not valid..."})
        usr_role_rights = []
        print("usr_role_checking")
        if role_info.id == 1 or role_info.id == 2:
            print("admin and superadmin")
            usr_rights = UserRights.objects.all()
            for i in range(0,len(usr_rights)):
                usr_role_rights.append(RoleRightsMapper(role=validated_data['role'],rights_id = i+1))
            RoleRightsMapper.objects.bulk_create(usr_role_rights)
        elif role_info.id == 3:
            print("operators")
            for i in range(1,4):
                usr_role_rights.append(RoleRightsMapper(role_id=validated_data['role'],rights_id = i+1))
            RoleRightsMapper.objects.bulk_create(usr_role_rights)
        else:
            print("noraml user")
            RoleRightsMapper.objects.create(role=validated_data['role'],rights_id=3)
        return instance



class LoginUserSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Invalid Details.")

class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = ('role_name','desc')

    def create(self,validated_data):
        usr_role_info = UserRole()
        usr_role_info.role_name = validated_data['role_name']
        usr_role_info.desc = validated_data['desc']
        usr_role_info.save()
        # usr_role_info = UserRole.objects.Create(**validated_data)
        return usr_role_info

class EditUserRoleSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField()
    class Meta:
        model = UserRole
        fields = ('role_name','desc','order_id','status','id')

    def update(self,instance,validated_data):
        print("updated")
        print("successfully")
        # instance.role_name = validated_data['role_name']
        instance.desc = validated_data['desc']
        instance.order_id = validated_data['order_id']
        instance.status = validated_data['status']
        instance.save
        print("dfdfdf",instance)
        return instance   

class UserRightSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRights
        fields = ('rights_name','desc')
        extra_kwargs = {
                'rights_name': {
                    'validators': [
                        UniqueValidator(
                            queryset=UserRights.objects.all()
                        )
                    ]
                }
            }

    def create(self,validated_data):
        usr_rights_info = UserRights()
        usr_rights_info.rights_name = validated_data['rights_name']
        usr_rights_info.desc = validated_data['desc']
        usr_rights_info.save()
        # usr_role_info = UserRole.objects.Create(**validated_data)
        return usr_rights_info

class EditUserRightsSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField()
    class Meta:
        model = UserRights
        fields = ('id','rights_name','desc','order_id','status')
        extra_kwargs = {
                'rights_name': {
                    'validators': [
                        UniqueValidator(
                            queryset=UserRights.objects.all()
                        )
                    ]
                }
            }

    def update(self,instance,validated_data):
        print("updated")
        print("successfully")
        instance.rights_name = validated_data['rights_name']
        instance.desc = validated_data['desc']
        instance.order_id = validated_data['order_id']
        instance.status = validated_data['status']
        instance.save()
        print("dfdfdf",instance)
        return instance   

class UserIdSerializer(serializers.Serializer):
    usr_id = serializers.IntegerField()

class UserRoleIdSerializer(serializers.Serializer):
    role_id = serializers.IntegerField()

class UserRightsIdSerializer(serializers.Serializer):
    right_id = serializers.IntegerField()
