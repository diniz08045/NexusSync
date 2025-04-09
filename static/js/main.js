document.addEventListener('DOMContentLoaded', function() {
    // Initialize Feather icons
    feather.replace();
    
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Handle click-to-copy elements
    document.querySelectorAll('.click-to-copy').forEach(element => {
        element.addEventListener('click', function() {
            const text = this.textContent;
            navigator.clipboard.writeText(text).then(() => {
                // Show feedback
                const originalText = this.innerHTML;
                this.innerHTML = '<i data-feather="check" class="feather-sm"></i> Copied!';
                feather.replace();
                
                // Reset after 2 seconds
                setTimeout(() => {
                    this.innerHTML = originalText;
                    feather.replace();
                }, 2000);
            });
        });
    });
    
    // Add confirmation for dangerous actions
    document.querySelectorAll('[data-confirm]').forEach(element => {
        element.addEventListener('click', function(e) {
            const message = this.getAttribute('data-confirm') || 'Are you sure you want to proceed?';
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });
    
    // Handle auto-dismissing alerts
    document.querySelectorAll('.alert-auto-dismiss').forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000); // Dismiss after 5 seconds
    });
    
    // Add date-time formatting to elements with data-datetime attribute
    document.querySelectorAll('[data-datetime]').forEach(element => {
        const datetime = element.getAttribute('data-datetime');
        const date = new Date(datetime);
        element.textContent = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    });
    
    // Handle form validation styling
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            form.classList.add('was-validated');
        }, false);
    });
});
