from django.db import models


# Create your models here.

from django.contrib.auth.models import User

class Note(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    categorize_note=models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    favorite=models.BooleanField(default=False)
    


class SharedNote(models.Model):
    note = models.ForeignKey(Note, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)


class Group(models.Model):
    name = models.CharField(max_length=100)

class Membership(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    role = models.CharField(max_length=20)  # editor or viewer

class Task(models.Model):
    title = models.CharField(max_length=100)
    content = models.TextField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    due_date=models.DateField()
    
    # where will we give the attachment??
    
class Todo(models.Model):
    title=models.CharField(max_length=100)
    description=models.TextField()
    created_time=models.DateTimeField(auto_now_add=True)
    reminded_date=models.DateTimeField()
    status=models.BooleanField(default=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    # reminded_time=models.TimeField()
    