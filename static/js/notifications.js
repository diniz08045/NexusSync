document.addEventListener('DOMContentLoaded', function() {
    const container = document.getElementById('notifications-container');
    const paginationContainer = document.getElementById('pagination-container');
    const markAllReadBtn = document.getElementById('mark-all-read');
    
    let currentPage = 1;
    let totalPages = 1;
    const perPage = 10;
    
    // Load notifications
    function loadNotifications(page = 1) {
        currentPage = page;
        
        // Show loading spinner
        container.innerHTML = `
            <div class="d-flex justify-content-center my-5">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        `;
        
        fetch(`/api/notifications?page=${page}&per_page=${perPage}`)
            .then(response => response.json())
            .then(data => {
                renderNotifications(data.notifications);
                renderPagination(data.page, data.pages, data.total);
            })
            .catch(error => {
                console.error('Error fetching notifications:', error);
                container.innerHTML = `
                    <div class="alert alert-danger">
                        <i data-feather="alert-circle" class="feather-sm me-2"></i>
                        Error loading notifications. Please try again later.
                    </div>
                `;
                feather.replace();
            });
    }
    
    // Render notifications
    function renderNotifications(notifications) {
        if (notifications.length === 0) {
            const emptyTemplate = document.getElementById('empty-template');
            container.innerHTML = '';
            container.appendChild(document.importNode(emptyTemplate.content, true));
            feather.replace();
            return;
        }
        
        const template = document.getElementById('notification-template');
        container.innerHTML = '';
        
        notifications.forEach(notification => {
            const notificationNode = document.importNode(template.content, true);
            const item = notificationNode.querySelector('.notification-item');
            
            // Set data attributes and classes
            item.dataset.id = notification.id;
            if (!notification.is_read) {
                item.classList.add('unread', 'border-start', 'border-primary', 'border-3');
            }
            
            // Set content
            notificationNode.querySelector('.notification-title').textContent = notification.title;
            notificationNode.querySelector('.notification-message').textContent = notification.message;
            
            // Format date
            const date = new Date(notification.created_at);
            const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
            notificationNode.querySelector('.notification-date').textContent = formattedDate;
            
            // Handle button visibility
            const markReadBtn = notificationNode.querySelector('.mark-read-btn');
            if (notification.is_read) {
                markReadBtn.style.display = 'none';
            }
            
            container.appendChild(notificationNode);
        });
        
        // Replace feather icons
        feather.replace();
        
        // Add event listeners to buttons
        addButtonEventListeners();
    }
    
    // Add event listeners to notification action buttons
    function addButtonEventListeners() {
        // Mark as read buttons
        document.querySelectorAll('.mark-read-btn').forEach(button => {
            button.addEventListener('click', function() {
                const notificationId = this.closest('.notification-item').dataset.id;
                markAsRead(notificationId);
            });
        });
        
        // Dismiss buttons
        document.querySelectorAll('.dismiss-btn').forEach(button => {
            button.addEventListener('click', function() {
                const notificationId = this.closest('.notification-item').dataset.id;
                dismissNotification(notificationId);
            });
        });
    }
    
    // Mark notification as read
    function markAsRead(notificationId) {
        fetch(`/api/notifications/mark_read/${notificationId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const item = document.querySelector(`.notification-item[data-id="${notificationId}"]`);
                item.classList.remove('unread', 'border-start', 'border-primary', 'border-3');
                const markReadBtn = item.querySelector('.mark-read-btn');
                markReadBtn.style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error marking notification as read:', error);
        });
    }
    
    // Dismiss notification
    function dismissNotification(notificationId) {
        fetch(`/api/notifications/dismiss/${notificationId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                const item = document.querySelector(`.notification-item[data-id="${notificationId}"]`);
                item.remove();
                
                // Check if there are no more notifications
                if (container.querySelectorAll('.notification-item').length === 0) {
                    loadNotifications(currentPage);
                }
            }
        })
        .catch(error => {
            console.error('Error dismissing notification:', error);
        });
    }
    
    // Render pagination
    function renderPagination(page, pages, total) {
        totalPages = pages;
        
        if (pages <= 1) {
            paginationContainer.innerHTML = '';
            return;
        }
        
        let paginationHTML = '<nav aria-label="Notifications pagination"><ul class="pagination">';
        
        // Previous button
        paginationHTML += `
            <li class="page-item ${page <= 1 ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${page - 1}" aria-label="Previous">
                    <span aria-hidden="true">&laquo;</span>
                </a>
            </li>
        `;
        
        // Page numbers
        const startPage = Math.max(1, page - 2);
        const endPage = Math.min(pages, page + 2);
        
        for (let i = startPage; i <= endPage; i++) {
            paginationHTML += `
                <li class="page-item ${i === page ? 'active' : ''}">
                    <a class="page-link" href="#" data-page="${i}">${i}</a>
                </li>
            `;
        }
        
        // Next button
        paginationHTML += `
            <li class="page-item ${page >= pages ? 'disabled' : ''}">
                <a class="page-link" href="#" data-page="${page + 1}" aria-label="Next">
                    <span aria-hidden="true">&raquo;</span>
                </a>
            </li>
        `;
        
        paginationHTML += '</ul></nav>';
        
        paginationContainer.innerHTML = paginationHTML;
        
        // Add event listeners to pagination links
        document.querySelectorAll('.page-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const page = parseInt(this.dataset.page);
                if (page > 0 && page <= totalPages) {
                    loadNotifications(page);
                }
            });
        });
    }
    
    // Mark all notifications as read
    markAllReadBtn.addEventListener('click', function() {
        const unreadItems = document.querySelectorAll('.notification-item.unread');
        
        if (unreadItems.length === 0) {
            return;
        }
        
        const promises = Array.from(unreadItems).map(item => {
            const notificationId = item.dataset.id;
            return fetch(`/api/notifications/mark_read/${notificationId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
        });
        
        Promise.all(promises)
            .then(() => {
                // Reload current page
                loadNotifications(currentPage);
            })
            .catch(error => {
                console.error('Error marking all notifications as read:', error);
            });
    });
    
    // Initialize by loading the first page of notifications
    loadNotifications();
});
