from django.test import TestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth.models import User


def test_upload_pcap_file(self):
    # Create a test PCAP file to upload
    pcap_file = SimpleUploadedFile("test.pcap", b"content")

    response = self.client.post(reverse("upload_pcap"), {"pcap_file": pcap_file})
    self.assertEqual(response.status_code, 302)  # Check for successful redirection

    # Verify that the uploaded file is stored in the database (assert count in NetworkPacket)
    self.assertEqual(NetworkPacket.objects.count(), 1)


def test_search_packets(self):
    response = self.client.get(reverse("search_packets"))
    self.assertEqual(response.status_code, 200)
    self.assertTemplateUsed(response, "search.html")

    # Test a valid search query
    response = self.client.post(reverse("search_packets"), {"keyword": "192.168.1.1"})
    self.assertEqual(response.status_code, 200)
    self.assertTemplateUsed(response, "search_results.html")

    # Test an empty search query
    response = self.client.post(reverse("search_packets"), {"keyword": ""})
    self.assertEqual(response.status_code, 200)
    self.assertTemplateUsed(response, "search.html")

    # Test a search query with no results
    response = self.client.post(reverse("search_packets"), {"keyword": "nonexistent"})
    self.assertEqual(response.status_code, 200)
    self.assertTemplateUsed(response, "search_results.html")
    self.assertContains(response, 'No results found for "nonexistent"')


def test_user_registration(self):
    response = self.client.get(reverse("register"))
    self.assertEqual(response.status_code, 200)

    # Test user registration
    response = self.client.post(
        reverse("register"),
        {"username": "testuser", "password1": "mypassword", "password2": "mypassword"},
    )
    self.assertEqual(response.status_code, 302)  # Check for successful redirection

    # Verify that the user is created
    self.assertTrue(User.objects.filter(username="testuser").exists())


def test_user_login(self):
    user = User.objects.create_user(username="testuser", password="mypassword")
    response = self.client.get(reverse("login"))
    self.assertEqual(response.status_code, 200)

    # Test user login
    response = self.client.post(
        reverse("login"), {"username": "testuser", "password": "mypassword"}
    )
    self.assertEqual(response.status_code, 302)  # Check for successful redirection

    # Verify that the user is logged in
    self.assertEqual(str(response.context["user"]), "testuser")


def test_user_logout(self):
    user = User.objects.create_user(username="testuser", password="mypassword")
    self.client.login(username="testuser", password="mypassword")
    response = self.client.get(reverse("logout"))
    self.assertEqual(response.status_code, 302)  # Check for successful redirection

    # Verify that the user is logged out
    self.assertFalse(response.context["user"].is_authenticated)


def test_analysis_feature(self):
    # Create test data for analysis
    # Perform analysis and check if the expected results match
    pass


def test_visualization_feature(self):
    # Create test data for visualization
    # Generate visualization and check if the expected plot data is present in the response
    pass
