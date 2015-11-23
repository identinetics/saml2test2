// Enable all tooltips, disabled by default in Bootstrap
$(function () {
    $("[data-toggle='tooltip']").tooltip({
        placement: 'bottom',
        container: 'body'
    });
});

// Populate modal with dynamic data when button is clicked: http://getbootstrap.com/javascript/#modals-related-target
$('#infoModal').on('show.bs.modal', function (event) {
    var button = $(event.relatedTarget); // Button that triggered the modal
    // Extract info from data-* attributes
    var title = button.data('title');
    var content = button.data('content');

    var modal = $(this);
    modal.find('#modalTitle').text(title);
    modal.find('.modal-body').html(content)
});