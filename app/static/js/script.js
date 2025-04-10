/* Custom JavaScript for NexusSync */

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Handle sidebar toggle for mobile
    const sidebarToggle = document.querySelector('.navbar-toggler');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function() {
            const sidebar = document.getElementById('sidebarMenu');
            if (sidebar) {
                if (window.innerWidth < 768) { // Only for mobile
                    if (sidebar.classList.contains('show')) {
                        sidebar.classList.remove('show');
                    } else {
                        sidebar.classList.add('show');
                    }
                }
            }
        });
    }
    
    // Automatically hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
    
    // Confirmation dialogs
    const confirmBtns = document.querySelectorAll('[data-confirm]');
    confirmBtns.forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            if (!confirm(this.getAttribute('data-confirm'))) {
                e.preventDefault();
            }
        });
    });
    
    // Form validation feedback
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
    
    // Task completion toggle
    const taskCheckboxes = document.querySelectorAll('.task-checkbox');
    taskCheckboxes.forEach(function(checkbox) {
        checkbox.addEventListener('change', function() {
            const taskId = this.getAttribute('data-task-id');
            const taskItem = document.getElementById('task-' + taskId);
            
            if (this.checked) {
                taskItem.classList.add('completed');
            } else {
                taskItem.classList.remove('completed');
            }
            
            // You can add AJAX call here to update task status
        });
    });
    
    // Handle notifications dropdown
    const notificationBtn = document.getElementById('notificationsDropdown');
    if (notificationBtn) {
        notificationBtn.addEventListener('click', function() {
            // Mark all as seen can be handled via AJAX
            const badge = document.querySelector('.notification-badge');
            if (badge) {
                badge.classList.add('d-none');
            }
        });
    }
});