// Simple column header sorting for technical analysis tables
class TableHeaderSorter {
    constructor() {
        this.sortStates = {};
        this.initializeHeaders();
    }

    initializeHeaders() {
        // Add click listeners to all table headers for sorting
        setTimeout(() => {
            // Note: F&O table (niftyTable) sorting disabled for real-time data stability
            this.setupTableSorting('camarillaTable');
            this.setupTableSorting('cprTable');
            this.setupTableSorting('fibonacciTable');
        }, 1000);
    }

    setupTableSorting(tableId) {
        const table = document.getElementById(tableId);
        if (!table) return;
        
        const headers = table.querySelectorAll('thead th');
        headers.forEach((header, index) => {
            header.style.cursor = 'pointer';
            header.style.userSelect = 'none';
            header.title = 'Click to sort';
            
            // Add sort icon
            if (!header.querySelector('.sort-icon')) {
                const icon = document.createElement('i');
                icon.className = 'fas fa-sort sort-icon ms-1';
                icon.style.opacity = '0.5';
                header.appendChild(icon);
            }
            
            header.addEventListener('click', () => {
                this.sortTable(tableId, index);
            });
        });
    }

    sortTable(tableId, columnIndex, preserveDirection = false) {
        const table = document.getElementById(tableId);
        if (!table) return;
        
        const tbody = table.querySelector('tbody');
        if (!tbody) return;
        
        const rows = Array.from(tbody.querySelectorAll('tr')).filter(row => 
            row.cells.length > 1
        );
        const header = table.querySelectorAll('thead th')[columnIndex];
        
        // Determine sort direction
        const currentDirection = header.getAttribute('data-sort-direction') || 'none';
        const newDirection = preserveDirection && currentDirection !== 'none' ? 
            currentDirection : 
            (currentDirection === 'asc' ? 'desc' : 'asc');
        
        // Reset all other header icons
        table.querySelectorAll('thead th .sort-icon').forEach(icon => {
            icon.className = 'fas fa-sort sort-icon ms-1';
            icon.style.opacity = '0.5';
        });
        table.querySelectorAll('thead th').forEach(h => {
            h.removeAttribute('data-sort-direction');
        });
        
        // Update current header
        header.setAttribute('data-sort-direction', newDirection);
        const icon = header.querySelector('.sort-icon');
        if (icon) {
            icon.className = `fas fa-sort-${newDirection === 'asc' ? 'up' : 'down'} sort-icon ms-1`;
            icon.style.opacity = '1';
        }
        
        // Sort rows
        rows.sort((a, b) => {
            const cellA = a.cells[columnIndex];
            const cellB = b.cells[columnIndex];
            
            if (!cellA || !cellB) return 0;
            
            let valueA = this.getCellValue(cellA);
            let valueB = this.getCellValue(cellB);
            
            // Handle numeric comparison
            const numA = parseFloat(valueA);
            const numB = parseFloat(valueB);
            
            if (!isNaN(numA) && !isNaN(numB)) {
                return newDirection === 'asc' ? numA - numB : numB - numA;
            }
            
            // String comparison
            const result = valueA.localeCompare(valueB);
            return newDirection === 'asc' ? result : -result;
        });
        
        // Reorder DOM
        const fragment = document.createDocumentFragment();
        rows.forEach(row => fragment.appendChild(row));
        tbody.appendChild(fragment);
    }

    getCellValue(cell) {
        // Extract clean text value from cell
        let value = cell.textContent || cell.innerText || '';
        
        // Remove currency symbols and common prefixes
        value = value.replace(/[₹$RS,\s]/g, '');
        
        // Handle percentage values
        if (value.includes('%')) {
            value = value.replace('%', '');
        }
        
        return value.trim();
    }
}

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', function() {
    window.tableSorter = new TableHeaderSorter();
});