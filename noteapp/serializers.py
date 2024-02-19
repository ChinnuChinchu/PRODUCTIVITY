# myapp/serializers.py
from rest_framework import serializers
from .models import *
from django.contrib.auth.models import User


class adminserializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['username','email','password']

    def create(self,validated_data):
        a=User.objects.create(username=validated_data['username'],email=validated_data['email'])
        a.set_password(validated_data['password'])
        a.save()
        return a
        
class loginserializer(serializers.Serializer):
    username=serializers.CharField(max_length=30)
    password=serializers.CharField(max_length=30)
        

class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = '__all__'

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'

class MembershipSerializer(serializers.ModelSerializer):
    class Meta:
        model = Membership
        fields = '__all__'

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'

class TodoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Todo
        fields = '__all__'
        
        
