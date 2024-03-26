function uploadFile() {
    var fileInput = document.getElementById('fileToUpload');
    var file = fileInput.files[0];
    var formData = new FormData();
    formData.append('file', file);
    formData.append('csrf_token', document.getElementById('csrf_token').value);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/upload', true);
    xhr.onload = function () {
        if (xhr.status === 200) {
            alert(xhr.responseText);
            location.reload();
        } else {
            alert(xhr.responseText);
            location.reload();
        }
    };
    xhr.send(formData);
}

$(window).load(function () {
    $(".trigger_popup_fricc").click(function () {
        $('.hover_bkgr_fricc').show();
    });
    $('.popupCloseButton').click(function () {
        $('.hover_bkgr_fricc').hide();
    });
});

popup = {
    init: function () {
        $('figure').click(function () {
            popup.open($(this));
        });

        $(document).on('click', '.popup img', function () {
            return false;
        }).on('click', '.popup', function () {
            popup.close();
        })
    },

    open: function ($figure) {
        $('.gallery').addClass('pop');
        $popup = $('<div class="popup" />').appendTo($('body'));
        $fig = $figure.clone().appendTo($('.popup'));
        $bg = $('<div class="bg" />').appendTo($('.popup'));
        $close = $('<div class="close"><svg><use xlink:href="#close"></use></svg></div>').appendTo($fig);
        $shadow = $('<div class="shadow" />').appendTo($fig);
        src = $('img', $fig).attr('src');
        $shadow.css({ backgroundImage: 'url(' + src + ')' });
        $bg.css({ backgroundImage: 'url(' + src + ')' });
        setTimeout(function () {
            $('.popup').addClass('pop');
        }, 10);
    },

    close: function () {
        $('.gallery, .popup').removeClass('pop');
        setTimeout(function () {
            $('.popup').remove()
        }, 100);
    }
}

popup.init()
