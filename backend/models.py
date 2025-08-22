from django.db import models


class User(models.Model):
    ROLE_CHOICES = [
        ('account_manager', 'Account Manager'),
        ('client', 'Client'),
    ]

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.CharField(max_length=255, unique=True)  # Encrypted
    phone = models.CharField(max_length=255)               # Encrypted
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "users"

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.role})"


class Document(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('signed', 'Signed'),
        ('completed', 'Completed'),
    ]

    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    file_path = models.FileField(upload_to='documents/')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "documents"

    def __str__(self):
        return self.title

class DocumentAssignment(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    assigned_to = models.ForeignKey(User, related_name='assignments_received', on_delete=models.CASCADE)
    assigned_by = models.ForeignKey(User, related_name='assignments_made', on_delete=models.CASCADE)
    position_x = models.FloatField()
    position_y = models.FloatField()
    placed_image = models.FileField(upload_to='previews/', null=True, blank=True)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "document_assignments"

class OTPVerification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=10)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        db_table = "otp_verification"

    def __str__(self):
        return f"OTP for {self.user.email} - {'Used' if self.is_used else 'Pending'}"

class SignedDocument(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    signed_by = models.ForeignKey(User, on_delete=models.CASCADE)
    signed_file = models.FileField(upload_to='signed_documents/')
    position_x = models.FloatField()
    position_y = models.FloatField()
    signed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "signed_documents"

    def __str__(self):
        return f"Signed: {self.document.title} by {self.signed_by.email}"


class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('sent', 'Sent'),
        ('opened', 'Opened'),
        ('signed', 'Signed'),
        ('rejected', 'Rejected'),
        ('downloaded', 'Downloaded'),
    ]

    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    performed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_logs"

    def __str__(self):
        return f"{self.action.title()} - {self.document.title}"

