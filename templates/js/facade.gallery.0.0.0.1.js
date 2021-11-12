class GallerySlider {
    constructor(id) {
        this.Slider = $("#" + id + ".gallery-slider");
        this.Track = $(this.Slider.find(".gallery-slider-track")[0]);
        // find position span
        var positionSpans = this.Slider.find(".gallery-position>span");
        if (positionSpans.length > 0) {
            this.PositionSpan = $(positionSpans[0]);
        }

        // get options
        var loop = this.Slider.data("loop");
        this.Options.loop = (loop === undefined) ? true : (loop != 0);

        var slides = this.Track.children(".gallery-slide");
        this.Length = slides.length;
        var self = this;

        if (this.Options.loop) {
            //   clone slides before and after
            $(slides.get().reverse()).each(function () {
                var s = $(this);
                var dataSlide = parseInt(s.data("slide"));
                var pClone = s.clone();
                pClone.attr("data-slide", dataSlide - self.Length);
                pClone.data("slide", dataSlide - self.Length);
                pClone.addClass("clone");
                // update linked slides
                pClone.find("button[data-slide]").each(function () {
                    $(this).attr("data-slide", $(this).data("slide") - this.Length);
                });
                pClone.prependTo(self.Track);
            });
            slides.each(function () {
                var s = $(this);
                var dataSlide = parseInt(s.data("slide"));
                var aClone = s.clone();
                aClone.attr("data-slide", dataSlide + self.Length);
                aClone.data("slide", dataSlide + self.Length);
                aClone.addClass("clone");
                // update linked slides
                aClone.find("button[data-slide]").each(function () {
                    $(this).attr("data-slide", $(this).data("slide") + self.Length);
                });
                aClone.appendTo(self.Track);
            });
        }
        //   populate this.SlidePositions
        this.SetSlidePositions();
        //   set touch event listener on .gallery_slider_track
        //   set end_touch event listener, snap to nearest index point
        this.Track.on("touchstart", function (evt) { self.eTouchStart(evt); });
        this.Track.on("touchend", function (evt) { self.eTouchEnd(evt); });
        this.Track.on("touchcancel", function (evt) { self.eTouchCancel(evt); });
        this.Track.on("touchmove", function (evt) { self.eTouchMove(evt); });
        //   set resize listener:
        $(window).resize(function () {
            //    re-calculate this.SlidePositions
            self.SetSlidePositions();
            //    this.Slide(this.CurrentSlide, false);
            self.Slide(self.CurrentSlide, false);
        });
        // Slide to 0
        this.Slide(0, false);
    }

    SetSlidePositions() {
        this.SlidePositions = [];
        var self = this;
        this.Track.children(".gallery-slide").each(function () {
            self.SlidePositions.push($(this).position().left);
        });
    }

    eTouchStart(evt) {
        //evt.preventDefault();
        if (this.touchInProgress) {
            return;
        }
        var touch = evt.changedTouches[0];
        this.touchInProgress = true;
        this.touchId = touch.identifier;
        this.touchStartTime = +new Date();
        this.touchStartX = touch.pageX;
        this.touchStartSliderX = this.SlidePositions[this.Options.loop ? this.CurrentSlide + this.Length : this.CurrentSlide];
        console.log("touch start", this.touchStartX, this.StartSliderX);
    }

    eTouchEnd(evt) {
        //evt.preventDefault();
        var touches = evt.changedTouches;
        var moveX, newSliderX;
        for (var i = 0; i < touches.length; i++) {
            if (touches[i].identifier != this.touchId) {
                continue;
            }

            moveX = touches[i].pageX - this.touchStartX;
            newSliderX = this.touchStartSliderX - moveX;
            this.Track.css({ "transform": "translate(-" + newSliderX + "px, 0)" });

            this.touchInProgress = false;
            this.touchId = null;

            var touchEndTime = +new Date();
            var elapsedTime = touchEndTime - this.touchStartTime;
            console.log(moveX, elapsedTime);
            if (Math.abs(moveX) > 100 && elapsedTime < 200) {
                this.Slide((moveX < 0) ? "next" : "prev");
                return;
            }

            // find closest slide to newSliderX
            var closestSlide = null;
            var closestDist = null;
            for (var i in this.SlidePositions) {
                var pos = this.SlidePositions[i];
                if (closestDist != null && closestDist < Math.abs(pos - newSliderX)) {
                    continue;
                }
                closestDist = Math.abs(pos - newSliderX);
                closestSlide = this.Options.loop ? i - this.Length : i;
            }
            this.Slide(closestSlide);
        }
    }

    eTouchCancel(evt) {
        // immediately cancel move. Return to current slide
        this.Slide(this.CurrentSlide);
        this.touchInProgress = false;
        this.touchId = null;
    }

    eTouchMove(evt) {
        //evt.preventDefault();
        var touches = evt.changedTouches;
        for (var i = 0; i < touches.length; i++) {
            if (touches[i].identifier != this.touchId) {
                continue;
            }

            var moveX = touches[i].pageX - this.touchStartX;
            var newSliderX = this.touchStartSliderX - moveX;
            this.Track.css({ "transform": "translate(-" + newSliderX + "px, 0)" });
        }
    }

    touchStartTime = 0;
    touchStartX = 0;
    touchStartSliderX = 0;
    touchInProgress = false;
    touchId = null;

    Slider = null;
    Track = null;
    PositionSpan = null;
    CurrentSlide = 0;
    Length = 0;
    SlidePositions = [];
    Options = {
        loop: true
    };

    Slide(dest, animate = true) {
        if (dest == "prev") {
            this.Slide(this.CurrentSlide - 1, animate);
            return;
        }
        if (dest == "next") {
            this.Slide(this.CurrentSlide + 1, animate);
            return;
        }
        var ndest = parseInt(dest);
        if (isNaN(ndest)) {
            console.warn("Not a valid destination slide: \"" + dest + "\"");
            return;
        }
        // Constrain dest within length
        this.CurrentSlide = Math.max(this.Options.loop ? -this.Length : 0, Math.min(ndest, ((this.Options.loop ? 2 : 1) * this.Length) - 1));
        if (animate) {
            this.Track.addClass("sliding");
        }
        this.Track.css({ "transform": "translate(-" + this.SlidePositions[this.CurrentSlide + (this.Options.loop ? this.Length : 0)] + "px, 0)" });
        setTimeout(function (self) { self.SlideAfter(); }, animate ? 500 : 0, this);
    }

    SlideAfter() {
        this.Track.removeClass("sliding");
        if (this.PositionSpan != null) {
            var posText = "" + ((this.CurrentSlide + this.Length) % this.Length + 1) + "/" + this.Length;
            this.PositionSpan.text(posText);
        }
        if (this.CurrentSlide >= 0 && this.CurrentSlide < this.Length) {
            return;
        }
        // cut to original in center
        this.Slide((this.CurrentSlide + this.Length) % this.Length, false);
    }
}

var gallerySliders = {};

function gallerySlidersInit() {
    // set up sliders
    //  for every .gallery-slider:
    $(".gallery-slider").each(function () {
        var id = $(this).attr("id");
        gallerySliders[id] = new GallerySlider(id);
    });
    //  for every .gallery-slider-control:
    $(".gallery-slider-control").each(function () {
        $(this).on("click", gallerySliderControlClicked);
    });
}

function gallerySliderControlClicked() {
    var target = $(this).data("target");
    // .data() seems to get data of original, not clone
    var slide = $(this).attr("data-slide");
    if (target === undefined || slide === undefined) {
        console.warn("Slider control missing target or slide.");
        return;
    }
    if (!(target in gallerySliders)) {
        console.warn("Target slider doesn't exist, or not initialized.");
        return;
    }
    gallerySliders[target].Slide(slide);
}

$(document).ready(function () {
    gallerySlidersInit();
});