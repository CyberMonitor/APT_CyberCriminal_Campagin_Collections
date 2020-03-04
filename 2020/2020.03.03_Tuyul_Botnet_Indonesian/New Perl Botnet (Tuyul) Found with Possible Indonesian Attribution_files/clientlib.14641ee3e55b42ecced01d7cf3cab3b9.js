var articleDynamicSlideshows = [];
var breakpoint1200Crossed = false;

$(document).ready(function() {
    $(".a28-article-tile-list-dynamic-albumLayout").each(function() {
      
       
        if ($(window).prop("innerWidth") < 1200) {
            if (articleDynamicSlideshows.length < 1) {
                $(".a28-article-tile-list-dynamic .swiper-container").each(
                    function() {
                        articleDynamicSlideshows.push(
                            a28initSlideshow($(this))
                        );
                    }
                );
            }
        }
    });

    $(window).resize(function() {
        if ($(window).prop("innerWidth") < 1200) {
           
            if (articleDynamicSlideshows.length < 1 && !breakpoint1200Crossed) {
                $(".a28-article-tile-list-dynamic .swiper-container").each(
                    function() {
                        articleDynamicSlideshows.push(
                            a28initSlideshow($(this))
                        );
                    }
                );
            }
            breakpoint1200Crossed = true;
        } else {
            if (breakpoint1200Crossed) {
                a28removeSlideshow();
                breakpoint1200Crossed = false;
            }
        }
    });
});

function a28initSlideshow($slideshowContainer) {
    var swiperSettings = {
        loop: true,
        autoplay: {
            delay: 10000
        },
        slidesPerView: "auto",
        slidesPerGroup: 1,
        centeredSlides: true,
        centerInsufficientSlides: true
    };

    var swiper = new Swiper($slideshowContainer, swiperSettings);
    return swiper;
}

function a28removeSlideshow() {
    for (var i = 0; i < articleDynamicSlideshows.length; i++) {
        articleDynamicSlideshows[i].destroy(true, true);
    }

    articleDynamicSlideshows = [];
}
