document.addEventListener('DOMContentLoaded', function() {
    // Get elements
    const searchInput = document.getElementById('globalSearch');
    const searchResults = document.getElementById('searchResults');
    
    // Exit if the search components aren't present on this page
    if (!searchInput || !searchResults) return;
    
    // Debounce function to limit API calls
    function debounce(func, wait) {
        let timeout;
        return function() {
            const context = this;
            const args = arguments;
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                func.apply(context, args);
            }, wait);
        };
    }
    
    // Function to perform search
    const performSearch = debounce(function(query) {
        if (query.length < 2) {
            searchResults.classList.remove('active');
            return;
        }
        
        // Fetch search results
        fetch(`/api/global-search?q=${encodeURIComponent(query)}`)
            .then(response => response.json())
            .then(data => {
                if (data.results && data.results.length > 0) {
                    renderSearchResults(data.results);
                    searchResults.classList.add('active');
                } else {
                    searchResults.innerHTML = '<div class="search-no-results">No results found</div>';
                    searchResults.classList.add('active');
                }
            })
            .catch(error => {
                console.error('Search error:', error);
                searchResults.innerHTML = '<div class="search-no-results">Error performing search</div>';
                searchResults.classList.add('active');
            });
    }, 300);
    
    // Function to render search results
    function renderSearchResults(results) {
        searchResults.innerHTML = '';
        
        results.forEach(result => {
            const resultItem = document.createElement('a');
            resultItem.href = result.url;
            resultItem.className = 'search-result-item';
            
            // Create icon element
            const iconElement = document.createElement('div');
            iconElement.className = 'search-result-icon';
            iconElement.innerHTML = `<i data-feather="${result.icon || 'file'}"></i>`;
            
            // Create content element
            const contentElement = document.createElement('div');
            contentElement.className = 'search-result-content';
            
            // Add title
            const titleElement = document.createElement('div');
            titleElement.className = 'search-result-title';
            titleElement.textContent = result.title;
            
            // Add description if available
            if (result.description) {
                const descElement = document.createElement('div');
                descElement.className = 'search-result-description';
                descElement.textContent = result.description;
                contentElement.appendChild(titleElement);
                contentElement.appendChild(descElement);
            } else {
                contentElement.appendChild(titleElement);
            }
            
            // Add category badge if available
            if (result.category) {
                const categoryElement = document.createElement('span');
                categoryElement.className = 'search-result-category';
                categoryElement.textContent = result.category;
                contentElement.appendChild(categoryElement);
            }
            
            // Assemble the result item
            resultItem.appendChild(iconElement);
            resultItem.appendChild(contentElement);
            searchResults.appendChild(resultItem);
        });
        
        // Initialize feather icons
        feather.replace();
    }
    
    // Event listener for input
    searchInput.addEventListener('input', function() {
        const query = this.value.trim();
        if (query.length >= 2) {
            performSearch(query);
        } else {
            searchResults.classList.remove('active');
        }
    });
    
    // Close search results when clicking outside
    document.addEventListener('click', function(event) {
        if (!searchInput.contains(event.target) && !searchResults.contains(event.target)) {
            searchResults.classList.remove('active');
        }
    });
    
    // Prevent form submission on Enter
    searchInput.addEventListener('keydown', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            
            // If results are active and there's at least one result, navigate to the first result
            if (searchResults.classList.contains('active')) {
                const firstResult = searchResults.querySelector('.search-result-item');
                if (firstResult) {
                    window.location.href = firstResult.href;
                }
            }
        }
    });
});