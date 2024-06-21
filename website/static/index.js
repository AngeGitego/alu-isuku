// index.js

// Example JavaScript function for frontend interaction
function deleteNote(noteId) {
    // Example AJAX request to delete a note
    fetch('/delete_note/' + noteId, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        if (response.ok) {
            // Update UI or display a success message
            console.log('Note deleted successfully.');
        } else {
            // Handle errors or display error message
            console.error('Error deleting note.');
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

// You can add more JavaScript functions here as needed
